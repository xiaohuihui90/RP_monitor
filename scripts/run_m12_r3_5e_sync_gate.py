#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import json
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


FINAL_STATES = {"success", "failed", "blocked"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def fetch_json(url: str, timeout: int) -> dict[str, Any]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = resp.read()
            text = data.decode("utf-8", errors="replace")
            return {
                "ok": True,
                "http_status": getattr(resp, "status", None),
                "url": url,
                "bytes": len(data),
                "json": json.loads(text),
                "error_class": None,
                "error_message": None,
            }
    except Exception as e:
        return {
            "ok": False,
            "http_status": getattr(e, "code", None),
            "url": url,
            "bytes": None,
            "json": None,
            "error_class": type(e).__name__,
            "error_message": str(e),
        }


def post_json(url: str, payload: dict[str, Any], timeout: int) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            text = raw.decode("utf-8", errors="replace")
            return {
                "ok": True,
                "http_status": getattr(resp, "status", None),
                "url": url,
                "bytes": len(raw),
                "json": json.loads(text) if text.strip() else {},
                "error_class": None,
                "error_message": None,
            }
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if hasattr(e, "read") else ""
        return {
            "ok": False,
            "http_status": e.code,
            "url": url,
            "bytes": len(body.encode("utf-8")),
            "json": None,
            "error_class": "HTTPError",
            "error_message": f"{e} body={body[:1000]}",
        }
    except Exception as e:
        return {
            "ok": False,
            "http_status": getattr(e, "code", None),
            "url": url,
            "bytes": None,
            "json": None,
            "error_class": type(e).__name__,
            "error_message": str(e),
        }


def compact_get(compact: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for k in keys:
        if k in compact:
            return compact.get(k)
    return default


def ensure_gate_dirs(gate_dir: Path, probes: dict[str, Any]) -> None:
    (gate_dir / "outputs").mkdir(parents=True, exist_ok=True)
    (gate_dir / "logs").mkdir(parents=True, exist_ok=True)
    for probe_id in probes:
        (gate_dir / "probe_exports" / probe_id).mkdir(parents=True, exist_ok=True)


def build_context(config: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    stamp = utc_stamp()

    gate_cfg = config["gate"]
    collector_cfg = config["collector"]

    source_run_id = args.source_run_id or f"{gate_cfg['source_run_id_prefix']}_{stamp}"
    gate_id = args.gate_id or f"{gate_cfg['gate_id_prefix']}_{stamp}"

    gate_dir = Path(args.output_base or collector_cfg["output_base_dir"]) / gate_id

    return {
        "gate_id": gate_id,
        "source_run_id": source_run_id,
        "gate_dir": gate_dir,
        "config": config,
    }


def build_gate_request(ctx: dict[str, Any]) -> dict[str, Any]:
    cfg = ctx["config"]
    gate_cfg = cfg["gate"]

    return {
        "schema": "s3.stage3.m12_r3.5e_sync_gate_request.v1",
        "created_at_utc": utc_now(),
        "gate_id": ctx["gate_id"],
        "source_run_id": ctx["source_run_id"],
        "method": gate_cfg["method"],
        "root_version": gate_cfg["root_version"],
        "evidence_level": gate_cfg["evidence_level"],
        "policy_fingerprint": gate_cfg["policy_fingerprint"],
        "probes": cfg["probes"],
    }


def run_preflight(ctx: dict[str, Any]) -> dict[str, Any]:
    cfg = ctx["config"]
    collector_cfg = cfg["collector"]
    api_timeout = int(collector_cfg.get("api_timeout_seconds", 60))
    gate_dir: Path = ctx["gate_dir"]

    result = {
        "schema": "s3.stage3.m12_r3.5e.preflight_summary.v1",
        "created_at_utc": utc_now(),
        "gate_id": ctx["gate_id"],
        "source_run_id": ctx["source_run_id"],
        "probes": {},
        "warnings": [],
        "blockers": [],
    }

    def one_probe(probe_id: str, meta: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        base = meta["base_url"].rstrip("/")
        out_dir = gate_dir / "probe_exports" / probe_id

        health = fetch_json(base + "/api/v1/health", timeout=api_timeout)
        output_summary = fetch_json(base + "/api/v1/rp/output-summary", timeout=api_timeout)
        jobs = fetch_json(base + "/api/v1/exports/effective-object/jobs?limit=5", timeout=api_timeout)

        write_json(out_dir / "preflight_health.json", health)
        write_json(out_dir / "preflight_output_summary.json", output_summary)
        write_json(out_dir / "preflight_jobs.json", jobs)

        rec = {
            "probe_id": probe_id,
            "location": meta.get("location"),
            "base_url": base,
            "health_ok": health["ok"],
            "output_summary_ok": output_summary["ok"],
            "jobs_ok": jobs["ok"],
            "health": health,
            "output_summary": output_summary,
            "jobs": jobs,
        }
        return probe_id, rec

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(cfg["probes"])) as ex:
        futs = [
            ex.submit(one_probe, probe_id, meta)
            for probe_id, meta in cfg["probes"].items()
        ]
        for fut in concurrent.futures.as_completed(futs):
            probe_id, rec = fut.result()
            result["probes"][probe_id] = rec

    for probe_id, rec in result["probes"].items():
        if not rec["health_ok"]:
            result["blockers"].append(f"{probe_id}:health_unreachable")
        if not rec["output_summary_ok"]:
            result["blockers"].append(f"{probe_id}:output_summary_unreachable")
        if not rec["jobs_ok"]:
            result["blockers"].append(f"{probe_id}:effective_object_jobs_unreachable")

        h = rec["health"].get("json") or {}
        if h.get("probe_id") and h.get("probe_id") != probe_id:
            result["warnings"].append(f"{probe_id}:health_probe_id_mismatch:{h.get('probe_id')}")

        o = rec["output_summary"].get("json") or {}
        if o.get("validator_state") not in (None, "ready"):
            result["warnings"].append(f"{probe_id}:validator_state_not_ready:{o.get('validator_state')}")

    result["status"] = "ok" if not result["blockers"] else "blocked"

    write_json(gate_dir / "outputs" / "preflight_summary.json", result)
    write_preflight_text(gate_dir, result)

    return result


def write_preflight_text(gate_dir: Path, result: dict[str, Any]) -> None:
    lines: list[str] = []
    lines.append(f"gate_id = {result['gate_id']}")
    lines.append(f"source_run_id = {result['source_run_id']}")
    lines.append(f"status = {result.get('status')}")
    lines.append(f"warnings = {result.get('warnings')}")
    lines.append(f"blockers = {result.get('blockers')}")
    lines.append("")

    for probe_id in sorted(result["probes"]):
        rec = result["probes"][probe_id]
        lines.append(f"=== {probe_id} {rec.get('location')} {rec.get('base_url')} ===")
        lines.append(f"health_ok = {rec.get('health_ok')}")
        h = rec.get("health", {}).get("json") or {}
        lines.append(f"  health.status = {h.get('status')}")
        lines.append(f"  health.probe_id = {h.get('probe_id')}")

        lines.append(f"output_summary_ok = {rec.get('output_summary_ok')}")
        o = rec.get("output_summary", {}).get("json") or {}
        for k in [
            "base_url",
            "validator_version",
            "validator_state",
            "vrp_count",
            "valid_manifests",
            "last_update_done",
            "status_summary_digest",
        ]:
            lines.append(f"  output_summary.{k} = {o.get(k)}")

        lines.append(f"jobs_ok = {rec.get('jobs_ok')}")
        j = rec.get("jobs", {}).get("json") or {}
        jobs = j.get("jobs", [])
        lines.append(f"  jobs_count_returned = {len(jobs)}")
        for item in jobs[:3]:
            lines.append(
                "  job "
                f"{item.get('export_id')} "
                f"status={item.get('status')} "
                f"source_run_id={item.get('source_run_id')} "
                f"compact_ready={item.get('compact_ready')} "
                f"records_ready={item.get('records_ready')}"
            )
        lines.append("")

    out = gate_dir / "outputs" / "99_m12_r3_5e_preflight_summary.txt"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_start_payload(ctx: dict[str, Any], probe_id: str, meta: dict[str, Any]) -> dict[str, Any]:
    gate_cfg = ctx["config"]["gate"]
    return {
        "source_run_id": ctx["source_run_id"],
        "probe_id": probe_id,
        "validator_id": meta["validator_id"],
        "probe_location": meta["location"],
        "method": gate_cfg["method"],
        "root_version": gate_cfg["root_version"],
        "evidence_level": gate_cfg["evidence_level"],
        "policy_fingerprint": gate_cfg["policy_fingerprint"],
        "force": True,
    }


def extract_export_id(response_json: dict[str, Any]) -> str | None:
    if not isinstance(response_json, dict):
        return None
    for k in ["export_id", "job_id", "id"]:
        if response_json.get(k):
            return str(response_json[k])
    for container_key in ["job", "data", "result"]:
        v = response_json.get(container_key)
        if isinstance(v, dict):
            for k in ["export_id", "job_id", "id"]:
                if v.get(k):
                    return str(v[k])
    return None


def start_exports(ctx: dict[str, Any]) -> dict[str, Any]:
    cfg = ctx["config"]
    collector_cfg = cfg["collector"]
    api_timeout = int(collector_cfg.get("api_timeout_seconds", 60))
    gate_dir: Path = ctx["gate_dir"]

    result = {
        "schema": "s3.stage3.m12_r3.5e.export_start_collection.v1",
        "created_at_utc": utc_now(),
        "gate_id": ctx["gate_id"],
        "source_run_id": ctx["source_run_id"],
        "probes": {},
        "warnings": [],
        "blockers": [],
    }

    def one_probe(probe_id: str, meta: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        base = meta["base_url"].rstrip("/")
        out_dir = gate_dir / "probe_exports" / probe_id
        payload = build_start_payload(ctx, probe_id, meta)
        start_url = base + "/api/v1/exports/effective-object/start"

        sent_at = utc_now()
        resp = post_json(start_url, payload, timeout=api_timeout)
        done_at = utc_now()

        write_json(out_dir / "start_request.json", payload)
        write_json(out_dir / "start_response.json", resp)

        export_id = extract_export_id(resp.get("json") or {})

        rec = {
            "probe_id": probe_id,
            "location": meta["location"],
            "base_url": base,
            "start_url": start_url,
            "collector_start_sent_at_utc": sent_at,
            "collector_start_done_at_utc": done_at,
            "ok": resp["ok"],
            "http_status": resp["http_status"],
            "export_id": export_id,
            "response_path": str(out_dir / "start_response.json"),
            "error_class": resp["error_class"],
            "error_message": resp["error_message"],
        }
        return probe_id, rec

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(cfg["probes"])) as ex:
        futs = [
            ex.submit(one_probe, probe_id, meta)
            for probe_id, meta in cfg["probes"].items()
        ]
        for fut in concurrent.futures.as_completed(futs):
            probe_id, rec = fut.result()
            result["probes"][probe_id] = rec

    for probe_id, rec in result["probes"].items():
        if not rec["ok"]:
            result["blockers"].append(f"{probe_id}:export_start_failed")
        elif not rec.get("export_id"):
            result["blockers"].append(f"{probe_id}:export_id_missing_from_start_response")

    result["status"] = "ok" if not result["blockers"] else "partial_or_failed"

    write_json(gate_dir / "outputs" / "probe_export_start_collection.json", result)
    return result


def poll_exports(ctx: dict[str, Any], start_result: dict[str, Any]) -> dict[str, Any]:
    cfg = ctx["config"]
    collector_cfg = cfg["collector"]
    api_timeout = int(collector_cfg.get("api_timeout_seconds", 60))
    poll_interval = int(collector_cfg.get("poll_interval_seconds", 10))
    export_timeout = int(collector_cfg.get("export_timeout_seconds", 3600))
    gate_dir: Path = ctx["gate_dir"]

    result = {
        "schema": "s3.stage3.m12_r3.5e.export_status_poll.v1",
        "created_at_utc": utc_now(),
        "gate_id": ctx["gate_id"],
        "source_run_id": ctx["source_run_id"],
        "started_poll_at_utc": utc_now(),
        "finished_poll_at_utc": None,
        "timeout_seconds": export_timeout,
        "poll_interval_seconds": poll_interval,
        "probes": {},
        "poll_history": [],
        "warnings": [],
        "blockers": [],
    }

    pending: dict[str, dict[str, Any]] = {}
    for probe_id, rec in start_result["probes"].items():
        if rec.get("export_id"):
            pending[probe_id] = rec
        else:
            result["probes"][probe_id] = {
                "probe_id": probe_id,
                "status": "start_failed_or_export_id_missing",
                "start_record": rec,
            }
            result["blockers"].append(f"{probe_id}:not_pollable")

    deadline = time.time() + export_timeout

    while pending and time.time() < deadline:
        tick = {
            "polled_at_utc": utc_now(),
            "statuses": {},
        }

        for probe_id in list(pending.keys()):
            rec = pending[probe_id]
            export_id = rec["export_id"]
            base = rec["base_url"].rstrip("/")
            url = base + f"/api/v1/exports/effective-object/{export_id}/status"

            status_resp = fetch_json(url, timeout=api_timeout)
            tick["statuses"][probe_id] = {
                "ok": status_resp["ok"],
                "http_status": status_resp["http_status"],
                "error_class": status_resp["error_class"],
                "error_message": status_resp["error_message"],
            }

            if not status_resp["ok"]:
                continue

            obj = status_resp["json"] or {}
            status = obj.get("status") or obj.get("state")

            tick["statuses"][probe_id]["status"] = status
            tick["statuses"][probe_id]["compact_ready"] = obj.get("compact_ready")
            tick["statuses"][probe_id]["records_ready"] = obj.get("records_ready")

            if status in FINAL_STATES:
                out_dir = gate_dir / "probe_exports" / probe_id
                write_json(out_dir / "final_status.json", obj)
                result["probes"][probe_id] = {
                    "probe_id": probe_id,
                    "export_id": export_id,
                    "base_url": base,
                    "status_url": url,
                    "status": status,
                    "final_status_path": str(out_dir / "final_status.json"),
                    "final_status": obj,
                }
                pending.pop(probe_id, None)

        result["poll_history"].append(tick)

        if pending:
            time.sleep(poll_interval)

    if pending:
        for probe_id, rec in pending.items():
            result["probes"][probe_id] = {
                "probe_id": probe_id,
                "export_id": rec.get("export_id"),
                "base_url": rec.get("base_url"),
                "status": "collector_poll_timeout",
            }
            result["blockers"].append(f"{probe_id}:collector_poll_timeout")

    result["finished_poll_at_utc"] = utc_now()

    for probe_id, rec in result["probes"].items():
        if rec.get("status") != "success":
            result["blockers"].append(f"{probe_id}:export_status_not_success:{rec.get('status')}")

    result["status"] = "ok" if not result["blockers"] else "partial_or_failed"

    write_json(gate_dir / "outputs" / "probe_export_status_poll.json", result)
    return result


def fetch_compacts(ctx: dict[str, Any], poll_result: dict[str, Any]) -> dict[str, Any]:
    cfg = ctx["config"]
    collector_cfg = cfg["collector"]
    compact_timeout = int(collector_cfg.get("compact_fetch_timeout_seconds", 120))
    gate_dir: Path = ctx["gate_dir"]

    result = {
        "schema": "s3.stage3.m12_r3.5e.probe_compact_collection.v1",
        "created_at_utc": utc_now(),
        "gate_id": ctx["gate_id"],
        "source_run_id": ctx["source_run_id"],
        "probes": {},
        "warnings": [],
        "blockers": [],
    }

    def one_probe(probe_id: str, rec: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        if rec.get("status") != "success":
            return probe_id, {
                "probe_id": probe_id,
                "status": "skip_non_success_export",
                "export_status": rec.get("status"),
            }

        export_id = rec["export_id"]
        base = rec["base_url"].rstrip("/")
        url = base + f"/api/v1/exports/effective-object/{export_id}/compact"
        out_dir = gate_dir / "probe_exports" / probe_id

        resp = fetch_json(url, timeout=compact_timeout)
        if resp["ok"]:
            write_json(out_dir / "compact.json", resp["json"])
            status = "success"
        else:
            status = "compact_fetch_failed"

        return probe_id, {
            "probe_id": probe_id,
            "base_url": base,
            "export_id": export_id,
            "compact_url": url,
            "status": status,
            "ok": resp["ok"],
            "http_status": resp["http_status"],
            "compact_path": str(out_dir / "compact.json") if resp["ok"] else None,
            "error_class": resp["error_class"],
            "error_message": resp["error_message"],
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(cfg["probes"])) as ex:
        futs = [
            ex.submit(one_probe, probe_id, rec)
            for probe_id, rec in poll_result["probes"].items()
        ]
        for fut in concurrent.futures.as_completed(futs):
            probe_id, rec = fut.result()
            result["probes"][probe_id] = rec

    for probe_id, rec in result["probes"].items():
        if rec.get("status") != "success":
            result["blockers"].append(f"{probe_id}:compact_not_collected")

    result["status"] = "ok" if not result["blockers"] else "partial_or_failed"

    write_json(gate_dir / "outputs" / "probe_compact_collection.json", result)
    return result


def validate_and_compare_compacts(ctx: dict[str, Any], compact_collection: dict[str, Any]) -> dict[str, Any]:
    cfg = ctx["config"]
    gate_cfg = cfg["gate"]
    thresholds = cfg.get("thresholds", {})
    gate_dir: Path = ctx["gate_dir"]

    active_manifest_min = int(thresholds.get("active_manifest_min", 50000))
    active_object_record_min = int(thresholds.get("active_object_record_min", 470000))
    expired_strict_max = int(thresholds.get("expired_manifest_strict_max", 100))
    expired_relaxed_max = int(thresholds.get("expired_manifest_relaxed_max", 1000))

    probes = {}
    root_groups = defaultdict(list)
    warnings = []
    blockers = []
    candidate_causes = []

    for probe_id, rec in compact_collection["probes"].items():
        if rec.get("status") != "success" or not rec.get("compact_path"):
            blockers.append(f"{probe_id}:compact_missing")
            probes[probe_id] = rec
            continue

        compact = read_json(Path(rec["compact_path"]))

        method = compact_get(compact, "source_method", "method")
        source_run_id = compact.get("source_run_id")
        root_version = compact.get("root_version")
        evidence_level = compact.get("evidence_level")
        policy_fp = compact.get("policy_fingerprint")
        root = compact.get("effective_object_root_v5")

        active_manifest_count = compact.get("active_manifest_count")
        expired_manifest_count = compact.get("expired_manifest_count")
        active_object_record_count = compact.get("active_object_record_count")
        freeze_window_clean = compact.get("freeze_window_clean")

        probe_blockers = []
        probe_warnings = []

        if compact.get("status") != "success":
            probe_blockers.append("compact_status_not_success")
        if compact.get("accepted_for_collector_object_gate_v5") is not True:
            probe_blockers.append("not_accepted_for_collector_object_gate_v5")
        if method != gate_cfg["method"]:
            probe_blockers.append("source_method_mismatch")
        if source_run_id != ctx["source_run_id"]:
            probe_blockers.append("source_run_id_mismatch")
        if root_version != gate_cfg["root_version"]:
            probe_blockers.append("root_version_mismatch")
        if evidence_level != gate_cfg["evidence_level"]:
            probe_blockers.append("evidence_level_mismatch")
        if policy_fp != gate_cfg["policy_fingerprint"]:
            probe_blockers.append("policy_fingerprint_mismatch")
        if not root:
            probe_blockers.append("root_missing")
        if compact.get("blockers"):
            probe_blockers.append("probe_compact_has_blockers")

        if freeze_window_clean is not True:
            probe_warnings.append("freeze_window_not_clean")

        if isinstance(active_manifest_count, int) and active_manifest_count < active_manifest_min:
            probe_blockers.append("active_manifest_count_below_min")
            candidate_causes.append(f"{probe_id}_low_active_manifest_count")

        if isinstance(active_object_record_count, int) and active_object_record_count < active_object_record_min:
            probe_blockers.append("active_object_record_count_below_min")
            candidate_causes.append(f"{probe_id}_low_active_object_record_count")

        if isinstance(expired_manifest_count, int):
            if expired_manifest_count >= expired_relaxed_max:
                probe_blockers.append("expired_manifest_count_too_high")
            elif expired_manifest_count >= expired_strict_max:
                probe_warnings.append("expired_manifest_count_above_strict_threshold")

        for b in probe_blockers:
            blockers.append(f"{probe_id}:{b}")
        for w in probe_warnings:
            warnings.append(f"{probe_id}:{w}")
        for w in compact.get("warnings") or []:
            warnings.append(f"{probe_id}:{w}")

        if root:
            root_groups[root].append(probe_id)

        probes[probe_id] = {
            "probe_id": probe_id,
            "location": cfg["probes"].get(probe_id, {}).get("location"),
            "export_id": rec.get("export_id"),
            "source_run_id": source_run_id,
            "status": compact.get("status"),
            "accepted_for_collector_object_gate_v5": compact.get("accepted_for_collector_object_gate_v5"),
            "source_method": method,
            "root_version": root_version,
            "evidence_level": evidence_level,
            "policy_fingerprint": policy_fp,
            "effective_object_root_v5": root,
            "active_manifest_count": active_manifest_count,
            "expired_manifest_count": expired_manifest_count,
            "active_object_record_count": active_object_record_count,
            "freeze_window_clean": freeze_window_clean,
            "blockers": compact.get("blockers"),
            "warnings": compact.get("warnings"),
            "compact_path": rec.get("compact_path"),
        }

    root_aligned = len(root_groups) == 1 and len(probes) == 3 and not blockers

    counts = {
        p: {
            "active_manifest_count": v.get("active_manifest_count"),
            "expired_manifest_count": v.get("expired_manifest_count"),
            "active_object_record_count": v.get("active_object_record_count"),
        }
        for p, v in probes.items()
        if isinstance(v, dict)
    }

    all_freeze_clean = all(
        v.get("freeze_window_clean") is True
        for v in probes.values()
        if isinstance(v, dict) and v.get("status") == "success"
    )

    bj = probes.get("probe-bj", {})
    if (
        bj.get("active_manifest_count", 0) >= active_manifest_min
        and bj.get("active_object_record_count", 0) >= active_object_record_min
        and bj.get("expired_manifest_count", 999999) < expired_strict_max
    ):
        candidate_causes.append("probe-bj_cache_source_fix_still_effective")
        candidate_causes.append("previous_probe-bj_low_count_anomaly_explained_by_wrong_or_stale_cache_source")

    if blockers:
        status = "blocked"
        confidence = "low"
        records_required = False
    elif root_aligned and all_freeze_clean:
        status = "aligned"
        confidence = "high"
        records_required = False
    elif root_aligned:
        status = "aligned"
        confidence = "medium"
        records_required = False
        warnings.append("root_aligned_but_freeze_window_not_clean")
    else:
        status = "divergent_candidate"
        confidence = "medium"
        records_required = True
        candidate_causes.append("object_layer_effective_root_divergence_candidate")
        if not all_freeze_clean:
            confidence = "low-to-medium"
            warnings.append("root_diff_with_freeze_window_not_clean")

    summary = {
        "schema": "s3.stage3.m12_r3.object_gate_v5_5e_sync_compact.v1",
        "created_at_utc": utc_now(),
        "gate_id": ctx["gate_id"],
        "source_run_id": ctx["source_run_id"],
        "status": status,
        "root_aligned": root_aligned,
        "records_required": records_required,
        "records_fetched": False,
        "confidence": confidence,
        "root_groups": {str(k): v for k, v in root_groups.items()},
        "counts": counts,
        "probes": probes,
        "candidate_causes": sorted(set(candidate_causes)),
        "warnings": sorted(set(warnings)),
        "blockers": sorted(set(blockers)),
        "interpretation": build_interpretation(status, root_aligned, records_required, all_freeze_clean),
        "not_e4_reason": (
            "Current evidence is object-layer effective-object evidence. "
            "Validated output-layer VRP/root/digest comparison is not included."
        ),
    }

    write_json(gate_dir / "outputs" / "object_gate_v5_5e_sync_compact.json", summary)
    write_final_text_summary(gate_dir, summary)
    return summary


def build_interpretation(status: str, root_aligned: bool, records_required: bool, all_freeze_clean: bool) -> list[str]:
    if status == "aligned" and root_aligned:
        return [
            "All three probes produced the same effective_object_root_v5 under the same source_run_id.",
            "This supports that the Beijing cache-source fix recovered the object-layer effective view.",
            "No object-layer records diff is required for this 5E compact gate run.",
        ]
    if records_required:
        msg = [
            "Three-probe compact gate did not align on effective_object_root_v5.",
            "This is an object-layer divergent candidate, not an E4 validated-output conclusion.",
            "Manifest/object records diff is required before stronger attribution.",
        ]
        if not all_freeze_clean:
            msg.append("At least one probe has freeze_window_clean != True, so confidence is reduced.")
        return msg
    return [
        "5E compact gate did not produce a high-confidence aligned result.",
        "Check blockers and warnings before proceeding.",
    ]


def write_final_text_summary(gate_dir: Path, obj: dict[str, Any]) -> None:
    lines = []
    for k in [
        "gate_id",
        "source_run_id",
        "status",
        "root_aligned",
        "records_required",
        "records_fetched",
        "confidence",
        "candidate_causes",
        "warnings",
        "blockers",
        "not_e4_reason",
    ]:
        lines.append(f"{k} = {obj.get(k)}")

    lines.append("")
    lines.append("counts:")
    for probe_id, counts in obj.get("counts", {}).items():
        lines.append(f"  {probe_id} {counts}")

    lines.append("")
    lines.append("root_groups:")
    for root, probes in obj.get("root_groups", {}).items():
        lines.append(f"  {root} {probes}")

    lines.append("")
    lines.append("interpretation:")
    for item in obj.get("interpretation", []):
        lines.append(f" - {item}")

    out = gate_dir / "outputs" / "99_m12_r3_5e_sync_compact_summary.txt"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run(ctx: dict[str, Any], mode: str) -> dict[str, Any]:
    cfg = ctx["config"]
    gate_dir: Path = ctx["gate_dir"]
    ensure_gate_dirs(gate_dir, cfg["probes"])

    gate_request = build_gate_request(ctx)
    write_json(gate_dir / "gate_request.json", gate_request)

    preflight = run_preflight(ctx)

    if mode == "preflight-only":
        return preflight

    if preflight.get("blockers"):
        return {
            "status": "blocked",
            "stage": "preflight",
            "preflight": preflight,
        }

    start_result = start_exports(ctx)

    if mode == "start-only":
        return start_result

    poll_result = poll_exports(ctx, start_result)
    compact_collection = fetch_compacts(ctx, poll_result)
    return validate_and_compare_compacts(ctx, compact_collection)


def main() -> int:
    parser = argparse.ArgumentParser(description="M12-R3 5E sync effective object gate")
    parser.add_argument("--config", default="config/p3/m12_r3_5e_sync_gate.yaml")
    parser.add_argument(
        "--mode",
        choices=["preflight-only", "start-only", "compact"],
        default="preflight-only",
    )
    parser.add_argument("--source-run-id", default=None)
    parser.add_argument("--gate-id", default=None)
    parser.add_argument("--output-base", default=None)

    args = parser.parse_args()

    config = read_yaml(Path(args.config))
    ctx = build_context(config, args)

    print("M12_R3_5E_GATE_ID=", ctx["gate_id"])
    print("M12_R3_5E_SOURCE_RUN_ID=", ctx["source_run_id"])
    print("M12_R3_5E_GATE_DIR=", ctx["gate_dir"])
    print("MODE=", args.mode)

    try:
        result = run(ctx, args.mode)
        print()
        print("=== RESULT ===")
        print(json.dumps(result, ensure_ascii=False, indent=2)[:20000])
        print()
        print("GATE_DIR=", ctx["gate_dir"])
        return 0 if not result.get("blockers") else 2
    except Exception as e:
        err = {
            "schema": "s3.stage3.m12_r3.5e.collector_internal_error.v1",
            "created_at_utc": utc_now(),
            "gate_id": ctx["gate_id"],
            "source_run_id": ctx["source_run_id"],
            "failure_stage": "collector_internal",
            "error_class": type(e).__name__,
            "error_message": str(e),
        }
        gate_dir: Path = ctx["gate_dir"]
        ensure_gate_dirs(gate_dir, config["probes"])
        write_json(gate_dir / "outputs" / "collector_internal_error.json", err)
        print(json.dumps(err, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
