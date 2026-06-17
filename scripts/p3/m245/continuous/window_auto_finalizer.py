from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from scripts.p3.m245.continuous.window_inbox_resolver import resolve_window


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")


def first(r: dict, keys: list[str]):
    for k in keys:
        if k in r and r.get(k) is not None:
            return r.get(k)
    return None


def rel(d: dict) -> str:
    vals = [json.dumps(v, ensure_ascii=False, sort_keys=True) for v in d.values() if v is not None]
    if not vals:
        return "unknown"
    return "same" if len(set(vals)) == 1 else "divergent"


def parse_probe_status(check_path: Path) -> str:
    if not check_path.exists():
        return "MISSING"
    for line in check_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("M245_PROBE_WINDOW="):
            return line.split("=", 1)[1].strip()
    return "UNKNOWN"


def build_matrix(project_dir: Path, window_id: str, probe_run_dirs: dict[str, Path]) -> tuple[Path, dict]:
    run_dir = project_dir / "data/p3_collector/m245_three_layer_baseline/history" / f"m245_window_{window_id}"
    indexes = run_dir / "indexes"
    outputs = run_dir / "outputs"
    checks = run_dir / "checks"
    inputs = run_dir / "inputs"

    for d in [indexes, outputs, checks, inputs]:
        d.mkdir(parents=True, exist_ok=True)

    advertised, objects, validation, validator_ctx = [], [], [], []
    probe_status = {}
    hard_fail = []

    for probe, rd in probe_run_dirs.items():
        cp = rd / "checks" / "M245_probe_window_check.txt"
        status = parse_probe_status(cp)
        probe_status[probe] = status

        if status != "PASS":
            hard_fail.append(f"{probe}:probe_status_{status}")

        if cp.exists():
            (inputs / f"{probe}_M245_probe_window_check.txt").write_text(
                cp.read_text(encoding="utf-8", errors="replace"),
                encoding="utf-8",
            )

        advertised += read_jsonl(rd / "indexes" / "advertised_view_records.jsonl")
        objects += read_jsonl(rd / "indexes" / "object_view_light_records.jsonl")
        validation += read_jsonl(rd / "indexes" / "validation_output_light_records.jsonl")
        validator_ctx += read_jsonl(rd / "indexes" / "validator_context_records.jsonl")

    write_jsonl(indexes / "merged_advertised_view_records.jsonl", advertised)
    write_jsonl(indexes / "merged_object_view_light_records.jsonl", objects)
    write_jsonl(indexes / "merged_validation_output_light_records.jsonl", validation)
    write_jsonl(indexes / "merged_validator_context_records.jsonl", validator_ctx)

    pp_groups = defaultdict(list)
    for r in advertised:
        pp_groups[r.get("pp_id") or r.get("publication_point") or "unknown"].append(r)

    pp_status = {}
    for pp_id, rows in sorted(pp_groups.items()):
        by_probe = {r.get("probe_id"): r for r in rows}
        session = {p: first(r, ["session_id"]) for p, r in by_probe.items()}
        serial = {p: first(r, ["serial"]) for p, r in by_probe.items()}
        digest = {p: first(r, ["notif_digest", "notification_digest", "digest"]) for p, r in by_probe.items()}
        fetch = {p: first(r, ["fetch_status", "status"]) for p, r in by_probe.items()}
        latency = {p: first(r, ["latency_ms"]) for p, r in by_probe.items()}

        pp_status[pp_id] = {
            "session_by_probe": session,
            "serial_by_probe": serial,
            "notif_digest_by_probe": digest,
            "fetch_status_by_probe": fetch,
            "latency_ms_by_probe": latency,
            "session_relation": rel(session),
            "serial_relation": rel(serial),
            "notif_digest_relation": rel(digest),
            "fetch_status_relation": rel(fetch),
        }

    adv_div = any(
        s.get("session_relation") == "divergent"
        or s.get("serial_relation") == "divergent"
        or s.get("notif_digest_relation") == "divergent"
        or s.get("fetch_status_relation") == "divergent"
        for s in pp_status.values()
    )

    obj_by_probe = {r.get("probe_id"): r for r in objects}
    object_root = {p: first(r, ["object_set_root", "object_root"]) for p, r in obj_by_probe.items()}
    object_count = {p: first(r, ["object_count_total", "object_count"]) for p, r in obj_by_probe.items()}
    manifest_count = {p: first(r, ["manifest_count_total", "manifest_count"]) for p, r in obj_by_probe.items()}
    manifest_root = {p: first(r, ["manifest_summary_root", "manifest_root"]) for p, r in obj_by_probe.items()}

    object_view = {
        "object_set_root_by_probe": object_root,
        "object_count_by_probe": object_count,
        "manifest_count_by_probe": manifest_count,
        "manifest_summary_root_by_probe": manifest_root,
        "object_set_root_relation": rel(object_root),
        "object_count_relation": rel(object_count),
        "manifest_count_relation": rel(manifest_count),
        "manifest_summary_root_relation": rel(manifest_root),
    }

    obj_div = any(
        object_view.get(k) == "divergent"
        for k in [
            "object_set_root_relation",
            "object_count_relation",
            "manifest_count_relation",
            "manifest_summary_root_relation",
        ]
    )

    val_by_probe = {r.get("probe_id"): r for r in validation}
    vrp_count = {p: first(r, ["vrp_count"]) for p, r in val_by_probe.items()}
    vrp_root = {p: first(r, ["vrp_root", "vrp_digest"]) for p, r in val_by_probe.items()}
    export_status = {p: first(r, ["export_status"]) for p, r in val_by_probe.items()}
    quality = {p: first(r, ["validation_output_quality"]) for p, r in val_by_probe.items()}
    suspicious = {p: first(r, ["suspicious_low_count"]) for p, r in val_by_probe.items()}

    version = {}
    for r in validator_ctx:
        p = r.get("probe_id")
        version[p] = first(r, ["validator_version", "version"])

    validation_output = {
        "vrp_count_by_probe": vrp_count,
        "vrp_root_by_probe": vrp_root,
        "export_status_by_probe": export_status,
        "validation_output_quality_by_probe": quality,
        "suspicious_low_count_by_probe": suspicious,
        "validator_version_by_probe": version,
        "vrp_count_relation": rel(vrp_count),
        "vrp_root_relation": rel(vrp_root),
        "export_status_relation": rel(export_status),
        "validation_output_quality_relation": rel(quality),
        "validator_version_relation": rel(version),
    }

    val_div = any(
        validation_output.get(k) == "divergent"
        for k in [
            "vrp_count_relation",
            "vrp_root_relation",
            "export_status_relation",
            "validation_output_quality_relation",
            "validator_version_relation",
        ]
    )

    probe_health = {}
    for probe in ["probe-bj", "probe-cd", "probe-sg"]:
        problems = []
        q = quality.get(probe)
        vc = vrp_count.get(probe)
        sus = suspicious.get(probe)

        if probe_status.get(probe) != "PASS":
            problems.append("probe_not_pass")
        if q not in ("ok", "ok_but_latency_high"):
            problems.append(f"validation_quality_{q}")
        try:
            if vc is None or int(vc) < 500000:
                problems.append(f"vrp_count_low_{vc}")
        except Exception:
            problems.append(f"vrp_count_bad_{vc}")
        if str(sus).lower() == "true":
            problems.append("suspicious_low_count")

        probe_health[probe] = {
            "status": "ok" if not problems else "unhealthy",
            "problems": problems,
        }

    layer_status = {
        "advertised_view": "divergent" if adv_div else "consistent",
        "object_view": "divergent" if obj_div else "consistent",
        "validation_output": "divergent" if val_div else "consistent",
    }

    m25_reason = [k for k, v in layer_status.items() if v == "divergent"]

    matrix = {
        "schema": "s3.m245.three_layer_status_matrix.g3b.v1",
        "created_at_utc": utc_now(),
        "window_id": window_id,
        "probe_status": probe_status,
        "probe_health": probe_health,
        "run_mode": "scheduled",
        "time_alignment_quality": "late",
        "comparison_strength": "diagnostic_only",
        "strict_compare_allowed": False,
        "advertised_view": {"status": layer_status["advertised_view"], "pp_status": pp_status},
        "object_view": {"status": layer_status["object_view"], **object_view},
        "validation_output": {"status": layer_status["validation_output"], **validation_output},
        "layer_status": layer_status,
        "m25_trigger_required": bool(m25_reason),
        "m25_trigger_reason": m25_reason,
    }

    summary = {
        "schema": "s3.m245.window_summary.g3b.v1",
        "status": "PASS" if not hard_fail else "FAIL",
        "created_at_utc": utc_now(),
        "window_id": window_id,
        "run_dir": str(run_dir),
        "probe_count": len(probe_run_dirs),
        "probe_pass_count": sum(1 for v in probe_status.values() if v == "PASS"),
        "merged_advertised_view_records_count": len(advertised),
        "merged_object_view_light_records_count": len(objects),
        "merged_validation_output_light_records_count": len(validation),
        "merged_validator_context_records_count": len(validator_ctx),
        "time_alignment_quality": "late",
        "comparison_strength": "diagnostic_only",
        "strict_compare_allowed": False,
        "layer_status": layer_status,
        "m25_trigger_required": bool(m25_reason),
        "m25_trigger_reason": m25_reason,
        "hard_fail": hard_fail,
    }

    write_json(outputs / "M245_three_layer_status_matrix.json", matrix)
    write_json(outputs / "M245_window_summary.json", summary)

    check = checks / "M245_window_aggregation_check.txt"
    with check.open("w", encoding="utf-8") as f:
        f.write(f"M245_WINDOW_AGGREGATION={summary['status']}\n\n")
        f.write(f"created_at_utc = {summary['created_at_utc']}\n")
        f.write(f"window_id = {window_id}\n")
        f.write(f"run_dir = {run_dir}\n")
        f.write(f"probe_count = {summary['probe_count']}\n")
        f.write(f"probe_pass_count = {summary['probe_pass_count']}\n")
        f.write(f"merged_advertised_view_records_count = {summary['merged_advertised_view_records_count']}\n")
        f.write(f"merged_object_view_light_records_count = {summary['merged_object_view_light_records_count']}\n")
        f.write(f"merged_validation_output_light_records_count = {summary['merged_validation_output_light_records_count']}\n")
        f.write(f"merged_validator_context_records_count = {summary['merged_validator_context_records_count']}\n")
        f.write(f"layer_status = {layer_status}\n")
        f.write(f"m25_trigger_required = {bool(m25_reason)}\n")
        f.write(f"m25_trigger_reason = {m25_reason}\n")
        f.write(f"hard_fail = {hard_fail}\n")

    return run_dir, summary, matrix


def run_diff(collector_run_dir: Path, window_id: str, matrix: dict) -> dict:
    indexes = collector_run_dir / "indexes"
    outputs = collector_run_dir / "outputs"
    checks = collector_run_dir / "checks"

    rows = []

    def add(layer, event_type, probe_values, reason, severity="medium", pp_id=None):
        rows.append({
            "schema": "s3.m245.g3b.diff_record.v1",
            "record_id": f"{layer}:{event_type}:{pp_id or 'global'}:{len(rows)+1:04d}",
            "window_id": window_id,
            "layer": layer,
            "source_layer": layer,
            "pp_id": pp_id,
            "event_type": event_type,
            "severity": severity,
            "probe_values": probe_values,
            "reason": reason,
            "created_at_utc": utc_now(),
        })

    for pp_id, s in (matrix.get("advertised_view", {}).get("pp_status", {}) or {}).items():
        for relation_key, event_type, value_key in [
            ("session_relation", "advertised_view_session_divergence", "session_by_probe"),
            ("serial_relation", "advertised_view_serial_skew", "serial_by_probe"),
            ("notif_digest_relation", "advertised_view_digest_divergence", "notif_digest_by_probe"),
            ("fetch_status_relation", "advertised_view_fetch_status_divergence", "fetch_status_by_probe"),
        ]:
            if s.get(relation_key) == "divergent":
                add("advertised_view", event_type, s.get(value_key, {}), f"{pp_id} {relation_key} divergent", "medium", pp_id)

    obj = matrix.get("object_view", {})
    for relation_key, event_type, value_key in [
        ("object_set_root_relation", "object_root_diff", "object_set_root_by_probe"),
        ("object_count_relation", "object_count_skew", "object_count_by_probe"),
        ("manifest_count_relation", "manifest_count_skew", "manifest_count_by_probe"),
        ("manifest_summary_root_relation", "manifest_summary_diff", "manifest_summary_root_by_probe"),
    ]:
        if obj.get(relation_key) == "divergent":
            add("object_view", event_type, obj.get(value_key, {}), f"{relation_key} divergent", "high" if "root" in relation_key else "medium")

    val = matrix.get("validation_output", {})
    for relation_key, event_type, value_key in [
        ("vrp_count_relation", "vrp_count_skew", "vrp_count_by_probe"),
        ("vrp_root_relation", "vrp_root_diff", "vrp_root_by_probe"),
        ("validation_output_quality_relation", "validation_output_quality_divergence", "validation_output_quality_by_probe"),
        ("validator_version_relation", "validator_version_divergence", "validator_version_by_probe"),
    ]:
        if val.get(relation_key) == "divergent":
            add("validation_output", event_type, val.get(value_key, {}), f"{relation_key} divergent", "high" if event_type == "vrp_root_diff" else "medium")

    baseline = []
    triggers = []
    for i, r in enumerate(rows, 1):
        baseline.append({
            **r,
            "schema": "s3.m245.g3b.baseline_diff_record.v1",
            "baseline_diff_id": f"bdiff-{i:04d}",
            "comparison_strength": "diagnostic_only",
            "strict_compare_allowed": False,
            "time_alignment_quality": "late",
        })
        triggers.append({
            "schema": "s3.m245.g3b.m25_trigger_candidate_record.v1",
            "trigger_id": f"m25-trigger-{window_id}-{i:04d}",
            "window_id": window_id,
            "source_layer": r["layer"],
            "pp_id": r.get("pp_id"),
            "event_type": r["event_type"],
            "trigger_strength": "diagnostic_only",
            "strict_compare_allowed": False,
            "time_alignment_quality": "late",
            "needs_m25_basic_attribution": True,
            "needs_deep_object_diff": r["layer"] == "object_view",
            "needs_vrp_source_uri_expansion": r["layer"] == "validation_output",
            "probe_values": r["probe_values"],
            "reason": r["reason"],
            "created_at_utc": utc_now(),
        })

    write_jsonl(indexes / "m245_diff_explanation_records.jsonl", rows)
    write_jsonl(indexes / "m245_baseline_diff_records.jsonl", baseline)
    write_jsonl(indexes / "m25_trigger_candidate_records.jsonl", triggers)

    by_layer = Counter(r["layer"] for r in rows)
    by_event = Counter(r["event_type"] for r in rows)

    status = "PASS" if rows else "PASS_NO_DIFF"
    summary = {
        "schema": "s3.m245.g3b.diff_trigger_summary.v1",
        "status": status,
        "created_at_utc": utc_now(),
        "window_id": window_id,
        "diff_explanation_count": len(rows),
        "baseline_diff_count": len(baseline),
        "m25_trigger_candidate_count": len(triggers),
        "by_layer": dict(by_layer),
        "by_event_type": dict(by_event),
        "time_alignment_quality": "late",
        "comparison_strength": "diagnostic_only",
        "strict_compare_allowed": False,
    }
    write_json(outputs / "M245_F2E_diff_trigger_summary.json", summary)

    with (checks / "M245_F2E_diff_trigger_check.txt").open("w", encoding="utf-8") as f:
        f.write(f"M245_F2E_DIFF_TRIGGER={status}\n\n")
        f.write(f"created_at_utc = {summary['created_at_utc']}\n")
        f.write(f"window_id = {window_id}\n")
        f.write(f"diff_explanation_count = {len(rows)}\n")
        f.write(f"baseline_diff_count = {len(baseline)}\n")
        f.write(f"m25_trigger_candidate_count = {len(triggers)}\n")
        f.write(f"by_layer = {dict(by_layer)}\n")
        f.write(f"by_event_type = {dict(by_event)}\n")
    return summary, triggers


def run_attribution(collector_run_dir: Path, window_id: str, matrix: dict, triggers: list[dict]) -> dict:
    indexes = collector_run_dir / "indexes"
    outputs = collector_run_dir / "outputs"
    checks = collector_run_dir / "checks"

    by_layer = Counter(t.get("source_layer") for t in triggers)
    by_event = Counter(t.get("event_type") for t in triggers)

    has_object = by_layer.get("object_view", 0) > 0
    has_validation = by_layer.get("validation_output", 0) > 0

    records = []
    for i, t in enumerate(triggers, 1):
        records.append({
            "schema": "s3.m25v0.g3b.basic_attribution_record.v1",
            "record_id": f"m25v0-attr-{i:04d}",
            "window_id": window_id,
            "trigger_id": t.get("trigger_id"),
            "source_layer": t.get("source_layer"),
            "event_type": t.get("event_type"),
            "strict_compare_allowed": False,
            "time_alignment_quality": "late",
            "trigger_strength": "diagnostic_only",
            "needs_deep_object_diff": t.get("source_layer") == "object_view",
            "needs_vrp_source_uri_expansion": t.get("source_layer") == "validation_output",
            "basic_status": "diagnostic_trigger_observed",
            "basic_attribution": "diagnostic_only_multilayer_divergence",
            "created_at_utc": utc_now(),
        })

    if not triggers:
        final_status = "all_layers_consistent"
        final_attr = "no_cross_probe_layer_divergence_observed"
        confidence = "medium"
    else:
        final_status = "insufficient_mapping_diagnostic_only"
        final_attr = "late_or_diagnostic_window_with_multilayer_divergence_observed"
        confidence = "medium-high"

    summary = {
        "schema": "s3.m25v0.g3b.basic_attribution_summary.v1",
        "status": "PASS",
        "created_at_utc": utc_now(),
        "window_id": window_id,
        "trigger_count": len(triggers),
        "basic_attribution_record_count": len(records),
        "by_layer": dict(by_layer),
        "by_event_type": dict(by_event),
        "final_status": final_status,
        "final_attribution": final_attr,
        "confidence": confidence,
        "needs_deep_object_diff": has_object,
        "needs_vrp_source_uri_expansion": has_validation,
        "vrp_impact_observed": has_validation,
        "time_alignment_quality": "late",
        "comparison_strength": "diagnostic_only",
        "strict_compare_allowed": False,
        "warnings": ["time_alignment_not_strict", "strict_compare_not_allowed"],
        "layer_status": matrix.get("layer_status"),
        "probe_health": matrix.get("probe_health"),
    }

    write_jsonl(indexes / "m25_basic_attribution_records.jsonl", records)
    write_json(outputs / "M25_basic_attribution_summary.json", summary)

    with (checks / "M25_basic_attribution_check.txt").open("w", encoding="utf-8") as f:
        f.write("M25_BASIC_ATTRIBUTION=PASS\n\n")
        f.write(f"created_at_utc = {summary['created_at_utc']}\n")
        f.write(f"window_id = {window_id}\n")
        f.write(f"trigger_count = {len(triggers)}\n")
        f.write(f"basic_attribution_record_count = {len(records)}\n")
        f.write(f"by_layer = {dict(by_layer)}\n")
        f.write(f"by_event_type = {dict(by_event)}\n")
        f.write(f"final_status = {final_status}\n")
        f.write(f"final_attribution = {final_attr}\n")
        f.write(f"confidence = {confidence}\n")
        f.write(f"needs_deep_object_diff = {has_object}\n")
        f.write(f"needs_vrp_source_uri_expansion = {has_validation}\n")
        f.write(f"vrp_impact_observed = {has_validation}\n")
        f.write(f"warnings = {summary['warnings']}\n")
    return summary


def run_loop(collector_run_dir: Path, window_id: str, matrix: dict, diff: dict, attr: dict) -> dict:
    outputs = collector_run_dir / "outputs"
    checks = collector_run_dir / "checks"

    required = [
        outputs / "M245_three_layer_status_matrix.json",
        outputs / "M245_F2E_diff_trigger_summary.json",
        outputs / "M25_basic_attribution_summary.json",
        collector_run_dir / "indexes" / "m25_trigger_candidate_records.jsonl",
        collector_run_dir / "indexes" / "m25_basic_attribution_records.jsonl",
    ]
    hard_fail = [f"missing_file:{p}" for p in required if not p.exists()]
    status = "PASS" if not hard_fail else "FAIL"

    probe_status = matrix.get("probe_status", {})
    probe_health = matrix.get("probe_health", {})

    summary = {
        "schema": "s3.three_layer_baseline_loop.g3b.summary.v1",
        "status": status,
        "created_at_utc": utc_now(),
        "window_id": window_id,
        "collector_run_dir": str(collector_run_dir),
        "probe_count": len(probe_status),
        "probe_pass_count": sum(1 for v in probe_status.values() if v == "PASS"),
        "probe_health_ok_count": sum(1 for h in probe_health.values() if h.get("status") == "ok"),
        "layer_status": matrix.get("layer_status"),
        "m25_trigger_required": matrix.get("m25_trigger_required"),
        "m25_trigger_reason": matrix.get("m25_trigger_reason"),
        "diff_explanation_count": diff.get("diff_explanation_count"),
        "baseline_diff_count": diff.get("baseline_diff_count"),
        "m25_trigger_candidate_count": diff.get("m25_trigger_candidate_count"),
        "basic_attribution_record_count": attr.get("basic_attribution_record_count"),
        "final_status": attr.get("final_status"),
        "final_attribution": attr.get("final_attribution"),
        "confidence": attr.get("confidence"),
        "needs_deep_object_diff": attr.get("needs_deep_object_diff"),
        "needs_vrp_source_uri_expansion": attr.get("needs_vrp_source_uri_expansion"),
        "vrp_impact_observed": attr.get("vrp_impact_observed"),
        "warnings": attr.get("warnings"),
        "time_alignment_quality": "late",
        "comparison_strength": "diagnostic_only",
        "strict_compare_allowed": False,
        "hard_fail": hard_fail,
    }

    write_json(outputs / "THREE_LAYER_BASELINE_LOOP_SUMMARY.json", summary)

    with (checks / "THREE_LAYER_BASELINE_LOOP_CHECK.txt").open("w", encoding="utf-8") as f:
        f.write(f"THREE_LAYER_BASELINE_LOOP={status}\n\n")
        f.write(f"created_at_utc = {summary['created_at_utc']}\n")
        f.write(f"window_id = {window_id}\n")
        f.write(f"collector_run_dir = {collector_run_dir}\n")
        f.write(f"probe_count = {summary['probe_count']}\n")
        f.write(f"probe_pass_count = {summary['probe_pass_count']}\n")
        f.write(f"probe_health_ok_count = {summary['probe_health_ok_count']}\n")
        f.write(f"layer_status = {summary['layer_status']}\n")
        f.write(f"m25_trigger_required = {summary['m25_trigger_required']}\n")
        f.write(f"m25_trigger_reason = {summary['m25_trigger_reason']}\n")
        f.write(f"diff_explanation_count = {summary['diff_explanation_count']}\n")
        f.write(f"baseline_diff_count = {summary['baseline_diff_count']}\n")
        f.write(f"m25_trigger_candidate_count = {summary['m25_trigger_candidate_count']}\n")
        f.write(f"basic_attribution_record_count = {summary['basic_attribution_record_count']}\n")
        f.write(f"final_status = {summary['final_status']}\n")
        f.write(f"final_attribution = {summary['final_attribution']}\n")
        f.write(f"confidence = {summary['confidence']}\n")
        f.write(f"needs_deep_object_diff = {summary['needs_deep_object_diff']}\n")
        f.write(f"needs_vrp_source_uri_expansion = {summary['needs_vrp_source_uri_expansion']}\n")
        f.write(f"vrp_impact_observed = {summary['vrp_impact_observed']}\n")
        f.write(f"warnings = {summary['warnings']}\n")
        f.write(f"hard_fail = {hard_fail}\n")
    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-dir", default=".")
    ap.add_argument("--window-id", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    project_dir = Path(args.project_dir).resolve()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    resolved = resolve_window(project_dir, args.window_id)
    write_json(out_dir / "M245_G3B_resolved_window.json", resolved)

    if not resolved.get("ready_for_finalizer"):
        status = "FAIL"
        check = out_dir / "M245_G3B_auto_finalizer_check.txt"
        with check.open("w", encoding="utf-8") as f:
            f.write("M245_G3B_AUTO_FINALIZER=FAIL\n")
            f.write(f"hard_fail = {resolved.get('hard_fail')}\n")
        print(f"M245_G3B_CHECK={check}")
        print(f"M245_G3B_STATUS={status}")
        return

    probe_run_dirs = {
        probe: Path(info["run_dir"])
        for probe, info in resolved["probe_results"].items()
    }

    collector_run_dir, aggregation, matrix = build_matrix(project_dir, args.window_id, probe_run_dirs)
    diff, triggers = run_diff(collector_run_dir, args.window_id, matrix)
    attr = run_attribution(collector_run_dir, args.window_id, matrix, triggers)
    loop = run_loop(collector_run_dir, args.window_id, matrix, diff, attr)

    for src in [
        collector_run_dir / "checks" / "M245_window_aggregation_check.txt",
        collector_run_dir / "checks" / "M245_F2E_diff_trigger_check.txt",
        collector_run_dir / "checks" / "M25_basic_attribution_check.txt",
        collector_run_dir / "checks" / "THREE_LAYER_BASELINE_LOOP_CHECK.txt",
        collector_run_dir / "outputs" / "THREE_LAYER_BASELINE_LOOP_SUMMARY.json",
    ]:
        if src.exists():
            (out_dir / src.name).write_bytes(src.read_bytes())

    check = out_dir / "M245_G3B_auto_finalizer_check.txt"
    status = loop.get("status")
    with check.open("w", encoding="utf-8") as f:
        f.write(f"M245_G3B_AUTO_FINALIZER={status}\n\n")
        f.write(f"created_at_utc = {utc_now()}\n")
        f.write(f"window_id = {args.window_id}\n")
        f.write(f"collector_run_dir = {collector_run_dir}\n")
        f.write(f"aggregation_status = {aggregation.get('status')}\n")
        f.write(f"diff_trigger_status = {diff.get('status')}\n")
        f.write(f"m25_basic_attribution_status = {attr.get('status')}\n")
        f.write(f"loop_status = {loop.get('status')}\n")
        f.write(f"final_status = {loop.get('final_status')}\n")
        f.write(f"final_attribution = {loop.get('final_attribution')}\n")
        f.write(f"confidence = {loop.get('confidence')}\n")
        f.write(f"hard_fail = {loop.get('hard_fail')}\n")

    print(f"M245_G3B_CHECK={check}")
    print(f"M245_G3B_COLLECTOR_RUN_DIR={collector_run_dir}")
    print(f"M245_G3B_STATUS={status}")
    print(f"final_status={loop.get('final_status')}")
    print(f"final_attribution={loop.get('final_attribution')}")


if __name__ == "__main__":
    main()
