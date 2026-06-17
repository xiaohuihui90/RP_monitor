from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import time
import traceback
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any

import requests

from shared.rrdp import compute_notif_digest, parse_notification


STATUS_PATH = Path("./data/object_shadow_worker_status.json")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_json(obj: Any) -> str:
    raw = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _sha256_bytes(raw)


def _safe_int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return default


@dataclass
class ObjectShadowSettings:
    interval_seconds: int
    timeout_seconds: int
    max_snapshot_bytes: int
    max_artifact_mb: int
    max_artifact_age_hours: int
    pp_filter: set[str] | None
    artifact_dir: Path
    status_path: Path


def _load_settings(config) -> ObjectShadowSettings:
    pp_ids = os.environ.get("S3_OBJECT_SHADOW_PP_IDS", "").strip()
    pp_filter = {x.strip() for x in pp_ids.split(",") if x.strip()} if pp_ids else None

    artifact_dir = Path(
        os.environ.get(
            "S3_OBJECT_SHADOW_DIR",
            f"./artifacts_phase2/{config.probe_id}/object_shadow",
        )
    )

    return ObjectShadowSettings(
        interval_seconds=_safe_int_env("S3_OBJECT_SHADOW_INTERVAL_SECONDS", max(int(config.poll_interval_seconds), 900)),
        timeout_seconds=_safe_int_env("S3_OBJECT_SHADOW_TIMEOUT_SECONDS", 60),
        max_snapshot_bytes=_safe_int_env("S3_OBJECT_SHADOW_MAX_SNAPSHOT_BYTES", 300_000_000),
        max_artifact_mb=_safe_int_env("S3_OBJECT_SHADOW_MAX_ARTIFACT_MB", 512),
        max_artifact_age_hours=_safe_int_env("S3_OBJECT_SHADOW_MAX_ARTIFACT_AGE_HOURS", 24),
        pp_filter=pp_filter,
        artifact_dir=artifact_dir,
        status_path=Path(os.environ.get("S3_OBJECT_SHADOW_STATUS_PATH", str(STATUS_PATH))),
    )


def _write_status(settings: ObjectShadowSettings, status: dict[str, Any]) -> None:
    settings.status_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = settings.status_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(status, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(settings.status_path)


def _read_status() -> dict[str, Any]:
    if not STATUS_PATH.exists():
        return {"enabled": False, "status": "not_started"}
    try:
        return json.loads(STATUS_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"enabled": False, "status": "status_read_failed", "error": str(exc)}


def _prune_artifacts(settings: ObjectShadowSettings) -> dict[str, Any]:
    root = settings.artifact_dir
    root.mkdir(parents=True, exist_ok=True)

    if "object_shadow" not in str(root):
        return {"skipped": True, "reason": "artifact_dir_not_object_shadow", "path": str(root)}

    now = time.time()
    max_age_sec = settings.max_artifact_age_hours * 3600
    max_bytes = settings.max_artifact_mb * 1024 * 1024

    files: list[tuple[float, int, Path]] = []
    deleted = 0
    deleted_bytes = 0

    for p in root.rglob("*"):
        if not p.is_file():
            continue
        try:
            st = p.stat()
        except FileNotFoundError:
            continue

        age = now - st.st_mtime
        if age > max_age_sec:
            size = st.st_size
            try:
                p.unlink()
                deleted += 1
                deleted_bytes += size
            except Exception:
                pass
        else:
            files.append((st.st_mtime, st.st_size, p))

    total = sum(size for _, size, _ in files)
    if total > max_bytes:
        for _, size, p in sorted(files, key=lambda x: x[0]):
            if total <= max_bytes:
                break
            try:
                p.unlink()
                total -= size
                deleted += 1
                deleted_bytes += size
            except Exception:
                pass

    return {
        "artifact_dir": str(root),
        "deleted_files": deleted,
        "deleted_bytes": deleted_bytes,
        "remaining_bytes_est": total,
        "max_artifact_mb": settings.max_artifact_mb,
        "max_artifact_age_hours": settings.max_artifact_age_hours,
    }


def _fetch_bytes(url: str, timeout: int, max_bytes: int) -> tuple[bytes, dict[str, str]]:
    with requests.get(url, timeout=timeout, stream=True) as r:
        r.raise_for_status()
        chunks: list[bytes] = []
        total = 0
        for chunk in r.iter_content(chunk_size=1024 * 1024):
            if not chunk:
                continue
            total += len(chunk)
            if total > max_bytes:
                raise RuntimeError(f"snapshot_too_large: {total} > {max_bytes}")
            chunks.append(chunk)
        return b"".join(chunks), dict(r.headers)


def _element_local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def _decode_publish_text(text: str | None) -> bytes:
    if not text:
        return b""
    compact = re.sub(r"\s+", "", text)
    try:
        return base64.b64decode(compact, validate=False)
    except Exception:
        return compact.encode("utf-8", errors="replace")


def _build_inventory_from_snapshot(snapshot_body: bytes) -> dict[str, Any]:
    object_count = 0
    leaves: list[str] = []
    sample_uris: list[str] = []

    for _event, elem in ET.iterparse(BytesIO(snapshot_body), events=("end",)):
        if _element_local_name(elem.tag) != "publish":
            elem.clear()
            continue

        uri = elem.attrib.get("uri") or ""
        hash_attr = elem.attrib.get("hash")

        if hash_attr:
            object_hash = hash_attr
        else:
            content = _decode_publish_text(elem.text)
            object_hash = _sha256_bytes(content)

        leaf = _sha256_json({"uri": uri, "hash": object_hash})
        leaves.append(leaf)
        object_count += 1

        if uri and len(sample_uris) < 20:
            sample_uris.append(uri)

        elem.clear()

    leaves.sort()
    object_set_root = _sha256_json(leaves)

    return {
        "object_count": object_count,
        "object_set_root": object_set_root,
        "sample_uris": sample_uris,
        "inventory_algorithm": "rrdp_snapshot_publish_uri_hash_v1",
    }


def _post_object_inventory(config, payload: dict[str, Any], timeout: int) -> None:
    url = config.collector_url.rstrip("/") + "/api/v1/object-inventory"
    r = requests.post(url, json=payload, timeout=timeout)
    r.raise_for_status()


def _collect_one_pp(config, pp, settings: ObjectShadowSettings) -> dict[str, Any]:
    started = _utcnow()

    notif_body, notif_headers = _fetch_bytes(
        pp.notification_uri,
        timeout=settings.timeout_seconds,
        max_bytes=10_000_000,
    )
    parsed = parse_notification(notif_body)

    snapshot_body, snapshot_headers = _fetch_bytes(
        parsed.snapshot_ref,
        timeout=settings.timeout_seconds,
        max_bytes=settings.max_snapshot_bytes,
    )

    inv = _build_inventory_from_snapshot(snapshot_body)

    timestamp = _utcnow()
    base_notif_digest = compute_notif_digest(parsed)

    inventory_digest = _sha256_json(
        {
            "pp_id": pp.pp_id,
            "session_id": parsed.session_id,
            "serial": parsed.serial,
            "snapshot_ref": parsed.snapshot_ref,
            "object_set_root": inv["object_set_root"],
            "object_count": inv["object_count"],
            "inventory_algorithm": inv["inventory_algorithm"],
        }
    )

    settings.artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_ref = str(
        settings.artifact_dir
        / f"{pp.pp_id}_{parsed.session_id}_{parsed.serial}_{config.probe_id}_inventory.json"
    )

    payload = {
        "schema_version": "2.0",
        "probe_id": config.probe_id,
        "location": getattr(config, "location", None),
        "timestamp": timestamp,
        "pp_id": pp.pp_id,
        "notification_uri": pp.notification_uri,
        "session_id": parsed.session_id,
        "serial": parsed.serial,
        "base_notif_digest": base_notif_digest,
        "inventory_source": "rrdp",
        "inventory_type": "snapshot",
        "snapshot_ref": parsed.snapshot_ref,
        "object_set_root": inv["object_set_root"],
        "object_count": inv["object_count"],
        "inventory_digest": inventory_digest,
        "bucket_roots_ref": None,
        "artifact_ref": artifact_ref,
        "inventory_build_stats": {
            "total_objects": inv["object_count"],
            "publish_count": inv["object_count"],
            "withdraw_count": 0,
            "invalid_item_count": 0,
            "algorithm": inv["inventory_algorithm"],
        },
        "sample_uris": inv["sample_uris"],
        "generated_at": timestamp,
        "started_at": started,
        "status": "ok",
        "notification_content_type": notif_headers.get("content-type") or notif_headers.get("Content-Type"),
        "snapshot_content_type": snapshot_headers.get("content-type") or snapshot_headers.get("Content-Type"),
        "snapshot_body_len": len(snapshot_body),
    }

    Path(artifact_ref).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    _post_object_inventory(config, payload, timeout=settings.timeout_seconds)

    return {
        "pp_id": pp.pp_id,
        "status": "ok",
        "session_id": parsed.session_id,
        "serial": parsed.serial,
        "object_count": inv["object_count"],
        "object_set_root": inv["object_set_root"],
        "inventory_digest": inventory_digest,
        "snapshot_body_len": len(snapshot_body),
        "artifact_ref": artifact_ref,
    }


def _collect_once_sync(config, settings: ObjectShadowSettings, status: dict[str, Any]) -> dict[str, Any]:
    cycle_started = _utcnow()
    results: list[dict[str, Any]] = []
    prune_result = _prune_artifacts(settings)

    for pp in config.pps:
        if settings.pp_filter and pp.pp_id not in settings.pp_filter:
            continue
        if not pp.enabled:
            continue

        try:
            result = _collect_one_pp(config, pp, settings)
        except Exception as exc:
            result = {
                "pp_id": pp.pp_id,
                "status": "fail",
                "error": str(exc),
                "exception_class": exc.__class__.__name__,
                "traceback_tail": traceback.format_exc().splitlines()[-8:],
            }

        results.append(result)
        status.update(
            {
                "enabled": True,
                "status": "running",
                "last_update": _utcnow(),
                "last_pp": pp.pp_id,
                "last_results": results,
                "prune_result": prune_result,
            }
        )
        _write_status(settings, status)

    ok = sum(1 for x in results if x.get("status") == "ok")
    fail = sum(1 for x in results if x.get("status") != "ok")

    status.update(
        {
            "enabled": True,
            "status": "sleeping",
            "cycle_started": cycle_started,
            "cycle_finished": _utcnow(),
            "ok_count": ok,
            "fail_count": fail,
            "last_results": results,
            "prune_result": prune_result,
            "artifact_dir": str(settings.artifact_dir),
            "next_interval_seconds": settings.interval_seconds,
        }
    )
    _write_status(settings, status)
    return status


async def _worker_loop(config) -> None:
    settings = _load_settings(config)
    status: dict[str, Any] = {
        "enabled": True,
        "status": "starting",
        "probe_id": config.probe_id,
        "started_at": _utcnow(),
        "artifact_dir": str(settings.artifact_dir),
        "interval_seconds": settings.interval_seconds,
        "max_snapshot_bytes": settings.max_snapshot_bytes,
        "max_artifact_mb": settings.max_artifact_mb,
    }
    _write_status(settings, status)

    print(f"[object_shadow_worker_started] probe_id={config.probe_id} interval={settings.interval_seconds}s dir={settings.artifact_dir}")

    while True:
        try:
            await asyncio.to_thread(_collect_once_sync, config, settings, status)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            status.update(
                {
                    "enabled": True,
                    "status": "worker_loop_error",
                    "last_error": str(exc),
                    "exception_class": exc.__class__.__name__,
                    "traceback_tail": traceback.format_exc().splitlines()[-12:],
                    "last_update": _utcnow(),
                }
            )
            _write_status(settings, status)
            print(f"[object_shadow_worker_error] {exc}")

        await asyncio.sleep(settings.interval_seconds)


def start_object_shadow_worker(config):
    return asyncio.create_task(_worker_loop(config))


def read_object_shadow_status() -> dict[str, Any]:
    return _read_status()


# ===== URI_HASH_INDEX_PATCH_START =====
# URI/hash index enhancement for object-layer deep diff.
# This block intentionally overrides _build_inventory_from_snapshot()
# and _collect_one_pp() defined above. It does not save RPKI object
# contents; it only saves uri -> hash JSONL index.

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _object_index_enabled() -> bool:
    return os.environ.get("S3_OBJECT_SHADOW_SAVE_INDEX", "0") == "1"


def _build_inventory_from_snapshot(snapshot_body: bytes) -> dict[str, Any]:
    object_count = 0
    leaves: list[str] = []
    sample_uris: list[str] = []
    entries: list[dict[str, str]] = []

    for _event, elem in ET.iterparse(BytesIO(snapshot_body), events=("end",)):
        if _element_local_name(elem.tag) != "publish":
            elem.clear()
            continue

        uri = elem.attrib.get("uri") or ""
        hash_attr = elem.attrib.get("hash")

        if hash_attr:
            object_hash = str(hash_attr).lower()
        else:
            content = _decode_publish_text(elem.text)
            object_hash = _sha256_bytes(content)

        leaf = _sha256_json({"uri": uri, "hash": object_hash})
        leaves.append(leaf)
        entries.append({"uri": uri, "hash": object_hash})
        object_count += 1

        if uri and len(sample_uris) < 20:
            sample_uris.append(uri)

        elem.clear()

    leaves.sort()
    entries.sort(key=lambda x: x["uri"])

    object_set_root = _sha256_json(leaves)

    return {
        "object_count": object_count,
        "object_set_root": object_set_root,
        "sample_uris": sample_uris,
        "inventory_algorithm": "rrdp_snapshot_publish_uri_hash_v1",
        "object_index_entries": entries,
    }


def _write_object_index_jsonl(
    *,
    settings: ObjectShadowSettings,
    pp_id: str,
    session_id: str,
    serial: int,
    probe_id: str,
    entries: list[dict[str, str]],
) -> dict[str, Any]:
    index_dir = settings.artifact_dir / "index"
    index_dir.mkdir(parents=True, exist_ok=True)

    path = index_dir / f"{pp_id}_{session_id}_{int(serial)}_{probe_id}_object_index.jsonl"
    tmp = path.with_suffix(".jsonl.tmp")

    with tmp.open("w", encoding="utf-8") as f:
        for item in entries:
            f.write(json.dumps(
                {"uri": item["uri"], "hash": item["hash"]},
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ))
            f.write("\n")

    tmp.replace(path)

    digest = _sha256_file(path)
    return {
        "object_index_ref": str(path),
        "object_index_digest": digest,
        "object_index_count": len(entries),
        "object_index_format": "jsonl_uri_hash_v1",
    }


def _collect_one_pp(config, pp, settings: ObjectShadowSettings) -> dict[str, Any]:
    started = _utcnow()

    notif_body, notif_headers = _fetch_bytes(
        pp.notification_uri,
        timeout=settings.timeout_seconds,
        max_bytes=10_000_000,
    )
    parsed = parse_notification(notif_body)

    snapshot_body, snapshot_headers = _fetch_bytes(
        parsed.snapshot_ref,
        timeout=settings.timeout_seconds,
        max_bytes=settings.max_snapshot_bytes,
    )

    inv = _build_inventory_from_snapshot(snapshot_body)

    timestamp = _utcnow()
    base_notif_digest = compute_notif_digest(parsed)

    index_info: dict[str, Any] = {}
    if _object_index_enabled():
        index_info = _write_object_index_jsonl(
            settings=settings,
            pp_id=pp.pp_id,
            session_id=parsed.session_id,
            serial=parsed.serial,
            probe_id=config.probe_id,
            entries=inv.get("object_index_entries", []),
        )

        try:
            from urllib.parse import urlencode
            q = urlencode({
                "pp_id": pp.pp_id,
                "session_id": parsed.session_id,
                "serial": int(parsed.serial),
            })
            index_info["object_index_url"] = (
                config.public_base_url.rstrip()
                + "/api/v1/object-shadow/index?"
                + q
            )
        except Exception:
            index_info["object_index_url"] = None

    inventory_digest = _sha256_json(
        {
            "pp_id": pp.pp_id,
            "session_id": parsed.session_id,
            "serial": parsed.serial,
            "snapshot_ref": parsed.snapshot_ref,
            "object_set_root": inv["object_set_root"],
            "object_count": inv["object_count"],
            "inventory_algorithm": inv["inventory_algorithm"],
            "object_index_digest": index_info.get("object_index_digest"),
        }
    )

    settings.artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_ref = str(
        settings.artifact_dir
        / f"{pp.pp_id}_{parsed.session_id}_{parsed.serial}_{config.probe_id}_inventory.json"
    )

    payload = {
        "schema_version": "2.1",
        "probe_id": config.probe_id,
        "location": getattr(config, "location", None),
        "timestamp": timestamp,
        "pp_id": pp.pp_id,
        "notification_uri": pp.notification_uri,
        "session_id": parsed.session_id,
        "serial": parsed.serial,
        "base_notif_digest": base_notif_digest,
        "inventory_source": "rrdp",
        "inventory_type": "snapshot",
        "snapshot_ref": parsed.snapshot_ref,
        "object_set_root": inv["object_set_root"],
        "object_count": inv["object_count"],
        "inventory_digest": inventory_digest,
        "bucket_roots_ref": None,
        "artifact_ref": artifact_ref,
        "inventory_build_stats": {
            "total_objects": inv["object_count"],
            "publish_count": inv["object_count"],
            "withdraw_count": 0,
            "invalid_item_count": 0,
            "algorithm": inv["inventory_algorithm"],
        },
        "sample_uris": inv["sample_uris"],
        "generated_at": timestamp,
        "started_at": started,
        "status": "ok",
        "notification_content_type": notif_headers.get("content-type") or notif_headers.get("Content-Type"),
        "snapshot_content_type": snapshot_headers.get("content-type") or snapshot_headers.get("Content-Type"),
        "snapshot_body_len": len(snapshot_body),
        **index_info,
    }

    Path(artifact_ref).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    _post_object_inventory(config, payload, timeout=settings.timeout_seconds)

    return {
        "pp_id": pp.pp_id,
        "status": "ok",
        "session_id": parsed.session_id,
        "serial": parsed.serial,
        "object_count": inv["object_count"],
        "object_set_root": inv["object_set_root"],
        "inventory_digest": inventory_digest,
        "snapshot_body_len": len(snapshot_body),
        "artifact_ref": artifact_ref,
        **index_info,
    }
# ===== URI_HASH_INDEX_PATCH_END =====

