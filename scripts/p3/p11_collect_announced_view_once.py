#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def utc_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sha256_bytes(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def safe_read_yaml_like(path: Path) -> dict[str, Any]:
    """
    Minimal YAML reader for the simple config used here.
    Avoids requiring PyYAML on all nodes.
    """
    text = path.read_text(encoding="utf-8")
    cfg: dict[str, Any] = {
        "snapshot_group_id": None,
        "collection_mode": "retrofit_or_diagnostic",
        "http": {"timeout_seconds": 20, "user_agent": "s3-radar-m15-announced-view/1.0"},
        "pp_scope": [],
        "output": {"out_root": "data/probe/e4a_announced_view", "store_raw_notification": True},
    }

    lines = text.splitlines()
    current = None
    current_item = None

    for raw in lines:
        line = raw.rstrip()
        s = line.strip()
        if not s or s.startswith("#"):
            continue

        if s.startswith("snapshot_group_id:"):
            cfg["snapshot_group_id"] = s.split(":", 1)[1].strip()
        elif s.startswith("collection_mode:"):
            cfg["collection_mode"] = s.split(":", 1)[1].strip()
        elif s == "http:":
            current = "http"
        elif s == "output:":
            current = "output"
        elif s == "pp_scope:":
            current = "pp_scope"
        elif current == "http" and ":" in s:
            k, v = s.split(":", 1)
            v = v.strip().strip('"')
            if k.strip() == "timeout_seconds":
                cfg["http"]["timeout_seconds"] = int(v)
            elif k.strip() == "user_agent":
                cfg["http"]["user_agent"] = v
        elif current == "output" and ":" in s:
            k, v = s.split(":", 1)
            v = v.strip()
            if k.strip() == "out_root":
                cfg["output"]["out_root"] = v
            elif k.strip() == "store_raw_notification":
                cfg["output"]["store_raw_notification"] = v.lower() == "true"
        elif current == "pp_scope":
            if s.startswith("- "):
                current_item = {}
                cfg["pp_scope"].append(current_item)
                rest = s[2:].strip()
                if ":" in rest:
                    k, v = rest.split(":", 1)
                    current_item[k.strip()] = parse_scalar(v.strip())
            elif current_item is not None and ":" in s:
                k, v = s.split(":", 1)
                current_item[k.strip()] = parse_scalar(v.strip())

    return cfg


def parse_scalar(v: str) -> Any:
    v = v.strip().strip('"').strip("'")
    if v.lower() == "true":
        return True
    if v.lower() == "false":
        return False
    return v


def local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def parse_notification_xml(xml_bytes: bytes) -> dict[str, Any]:
    root = ET.fromstring(xml_bytes)
    if local_name(root.tag) != "notification":
        raise ValueError(f"unexpected root tag: {root.tag}")

    session_id = root.attrib.get("session_id")
    serial_raw = root.attrib.get("serial")

    serial = None
    if serial_raw is not None:
        try:
            serial = int(serial_raw)
        except ValueError:
            serial = serial_raw

    snapshot_uri = None
    snapshot_hash = None
    deltas = []

    for child in list(root):
        name = local_name(child.tag)
        if name == "snapshot":
            snapshot_uri = child.attrib.get("uri")
            snapshot_hash = child.attrib.get("hash")
        elif name == "delta":
            d_serial_raw = child.attrib.get("serial")
            try:
                d_serial = int(d_serial_raw) if d_serial_raw is not None else None
            except ValueError:
                d_serial = d_serial_raw
            deltas.append({
                "serial": d_serial,
                "uri": child.attrib.get("uri"),
                "hash": child.attrib.get("hash"),
            })

    serial_values = [d["serial"] for d in deltas if isinstance(d.get("serial"), int)]

    chain_material = []
    for d in sorted(deltas, key=lambda x: str(x.get("serial"))):
        chain_material.append(f"{d.get('serial')}|{d.get('uri')}|{d.get('hash')}")
    delta_hash_chain_root = "sha256:" + hashlib.sha256("\n".join(chain_material).encode()).hexdigest()

    return {
        "session_id": session_id,
        "serial": serial,
        "snapshot_uri": snapshot_uri,
        "snapshot_hash": snapshot_hash,
        "delta_count": len(deltas),
        "delta_serial_min": min(serial_values) if serial_values else None,
        "delta_serial_max": max(serial_values) if serial_values else None,
        "delta_hash_chain_root": delta_hash_chain_root,
    }


def fetch_url(uri: str, timeout: int, user_agent: str) -> tuple[bytes | None, dict[str, Any]]:
    started = time.time()
    req = urllib.request.Request(uri, headers={"User-Agent": user_agent})
    meta: dict[str, Any] = {
        "fetch_status": "failed",
        "http_status": None,
        "latency_ms": None,
        "content_length": None,
        "etag": None,
        "last_modified": None,
        "failure_stage": None,
        "error_class": None,
        "error_message": None,
    }

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            meta["fetch_status"] = "success"
            meta["http_status"] = int(getattr(resp, "status", 200))
            meta["latency_ms"] = int((time.time() - started) * 1000)
            meta["content_length"] = len(body)
            meta["etag"] = resp.headers.get("ETag")
            meta["last_modified"] = resp.headers.get("Last-Modified")
            return body, meta
    except urllib.error.HTTPError as e:
        meta["http_status"] = e.code
        meta["latency_ms"] = int((time.time() - started) * 1000)
        meta["failure_stage"] = "notif_fetch"
        meta["error_class"] = "http_error"
        meta["error_message"] = str(e)
        return None, meta
    except TimeoutError as e:
        meta["latency_ms"] = int((time.time() - started) * 1000)
        meta["failure_stage"] = "notif_fetch"
        meta["error_class"] = "timeout"
        meta["error_message"] = str(e)
        return None, meta
    except Exception as e:
        meta["latency_ms"] = int((time.time() - started) * 1000)
        meta["failure_stage"] = "notif_fetch"
        meta["error_class"] = type(e).__name__
        meta["error_message"] = str(e)
        return None, meta


def build_root(records: list[dict[str, Any]]) -> str:
    canonical = []
    for r in records:
        canonical.append("|".join([
            str(r.get("pp_id")),
            str(r.get("notification_uri")),
            str(r.get("fetch_status")),
            str(r.get("session_id")),
            str(r.get("serial")),
            str(r.get("notification_digest")),
            str(r.get("snapshot_hash")),
            str(r.get("delta_hash_chain_root")),
        ]))
    material = "\n".join(sorted(canonical)).encode()
    return "sha256:" + hashlib.sha256(material).hexdigest()


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--snapshot-group-id", required=True)
    ap.add_argument("--probe-id", required=True)
    ap.add_argument("--location", required=True)
    ap.add_argument("--out-root", default=None)
    args = ap.parse_args()

    cfg = safe_read_yaml_like(Path(args.config))
    out_root = Path(args.out_root or cfg["output"]["out_root"])

    export_id = utc_compact()
    hist_dir = out_root / "history" / export_id
    latest_dir = out_root / "latest"
    raw_dir = hist_dir / "raw_notifications"

    hist_dir.mkdir(parents=True, exist_ok=True)
    latest_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)

    timeout = int(cfg.get("http", {}).get("timeout_seconds", 20))
    user_agent = cfg.get("http", {}).get("user_agent", "s3-radar-m15-announced-view/1.0")
    store_raw = bool(cfg.get("output", {}).get("store_raw_notification", True))

    records: list[dict[str, Any]] = []
    started_at = utc_now()

    for pp in cfg.get("pp_scope", []):
        if not pp.get("enabled", True):
            continue

        pp_id = pp["pp_id"]
        uri = pp["notification_uri"]
        collected_at = utc_now()

        body, fetch_meta = fetch_url(uri, timeout=timeout, user_agent=user_agent)

        base = {
            "schema": "s3.stage3.m15.announced_view_record.v1",
            "probe_id": args.probe_id,
            "location": args.location,
            "snapshot_group_id": args.snapshot_group_id,
            "collection_mode": cfg.get("collection_mode", "retrofit_or_diagnostic"),
            "export_id": export_id,
            "collected_at_utc": collected_at,
            "pp_id": pp_id,
            "rir": pp.get("rir"),
            "notification_uri": uri,
            "rrdp_fetch_mode": "notification_only",
            "rsync_fallback_observed": False,
        }
        base.update(fetch_meta)

        if body is not None and fetch_meta.get("fetch_status") == "success":
            try:
                parsed = parse_notification_xml(body)
                base.update(parsed)
                base["notification_digest"] = sha256_bytes(body)
                base["notification_digest_mode"] = "raw_bytes_sha256"
                base["failure_stage"] = None
                base["error_class"] = None
                base["error_message"] = None

                if store_raw:
                    raw_path = raw_dir / f"{pp_id}_notification.xml"
                    raw_path.write_bytes(body)
                    base["raw_notification_file"] = str(raw_path)
            except Exception as e:
                base.update({
                    "session_id": None,
                    "serial": None,
                    "notification_digest": sha256_bytes(body),
                    "notification_digest_mode": "raw_bytes_sha256",
                    "snapshot_uri": None,
                    "snapshot_hash": None,
                    "delta_count": 0,
                    "delta_serial_min": None,
                    "delta_serial_max": None,
                    "delta_hash_chain_root": None,
                    "fetch_status": "failed",
                    "failure_stage": "notif_parse",
                    "error_class": type(e).__name__,
                    "error_message": str(e),
                })
        else:
            base.update({
                "session_id": None,
                "serial": None,
                "notification_digest": None,
                "notification_digest_mode": "raw_bytes_sha256",
                "snapshot_uri": None,
                "snapshot_hash": None,
                "delta_count": 0,
                "delta_serial_min": None,
                "delta_serial_max": None,
                "delta_hash_chain_root": None,
            })

        records.append(base)

    finished_at = utc_now()
    success_count = sum(1 for r in records if r.get("fetch_status") == "success")
    failure_count = len(records) - success_count
    blockers = []
    warnings = []

    if not records:
        blockers.append("no_pp_records")
    if failure_count > 0:
        warnings.append("some_pp_fetch_failed")

    announced_view_root = build_root(records)

    records_file = hist_dir / "announced_view_records.jsonl"
    with records_file.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")

    summary = {
        "schema": "s3.stage3.m15.announced_view_probe_summary.v1",
        "probe_id": args.probe_id,
        "location": args.location,
        "snapshot_group_id": args.snapshot_group_id,
        "collection_mode": cfg.get("collection_mode", "retrofit_or_diagnostic"),
        "export_id": export_id,
        "pp_count": len(records),
        "success_count": success_count,
        "failure_count": failure_count,
        "announced_view_root_v1": announced_view_root,
        "records_file": str(records_file),
        "started_at_utc": started_at,
        "finished_at_utc": finished_at,
        "warnings": warnings,
        "blockers": blockers,
    }

    summary_file = hist_dir / "announced_view_probe_summary.json"
    write_json(summary_file, summary)

    sha_path = hist_dir / "sha256.txt"
    h_lines = []
    for p in [records_file, summary_file]:
        h_lines.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}")
    sha_path.write_text("\n".join(h_lines) + "\n", encoding="utf-8")

    acceptance = len(blockers) == 0
    acceptance_text = f"""P11_C_ANNOUNCED_VIEW_PROBE=DONE

created_at_utc = {utc_now()}

probe_id = {args.probe_id}
location = {args.location}
snapshot_group_id = {args.snapshot_group_id}
collection_mode = {cfg.get("collection_mode", "retrofit_or_diagnostic")}
export_id = {export_id}

pp_count = {len(records)}
success_count = {success_count}
failure_count = {failure_count}

announced_view_root_exists = True
records_exists = True
summary_exists = True
sha256_txt_exists = True

warnings = {warnings}
blockers = {blockers}

runtime_changes:
  collector_main_service_restarted = False
  probe_restarted = False
  new_validator_installed = False
  bgp_data_loaded = False
  cron_enabled = False

outputs:
  {records_file}
  {summary_file}
  {sha_path}

P11_C_probe_acceptance = {acceptance}
"""
    acc_file = hist_dir / "P11_C_announced_view_probe_acceptance.txt"
    acc_file.write_text(acceptance_text, encoding="utf-8")

    # update latest
    for src, name in [
        (records_file, "announced_view_records.jsonl"),
        (summary_file, "announced_view_probe_summary.json"),
        (sha_path, "sha256.txt"),
        (acc_file, "P11_C_announced_view_probe_acceptance.txt"),
    ]:
        (latest_dir / name).write_bytes(src.read_bytes())

    print(acceptance_text)

    if not acceptance:
        raise SystemExit("[BLOCKED] P11-C probe acceptance is False")


if __name__ == "__main__":
    main()
