#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_text(path: Path) -> str:
    if not path.exists() or not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_kv_text(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in read_text(path).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def parse_status(path: Path) -> tuple[str, str]:
    txt = read_text(path)
    m = re.search(r"^([A-Z0-9_]+)=(\S+)", txt, re.MULTILINE)
    if not m:
        return ("UNKNOWN_STATUS_KEY", "UNKNOWN")
    return (m.group(1), m.group(2))


def parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    value = value.strip().strip('"').strip("'")
    # Accept both 2026-06-03T12:37:22Z and 2026-06-03T12:37:22+00:00.
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def dt_to_z(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def as_int(x: Any, default: int = 0) -> int:
    try:
        return int(str(x).strip())
    except Exception:
        return default


def as_float(x: Any, default: float = 0.0) -> float:
    try:
        return float(str(x).strip())
    except Exception:
        return default


def seconds_to_human(sec: float | int | None) -> str:
    if sec is None:
        return "unknown"
    sec = float(sec)
    if sec < 60:
        return f"{sec:.1f}s"
    if sec < 3600:
        return f"{sec / 60:.2f}min"
    return f"{sec / 3600:.2f}h"


def find_timestamp(kv: dict[str, str]) -> tuple[str | None, datetime | None]:
    for key in ("generated_at_utc", "created_at_utc", "generated_at", "created_at", "started_at_utc", "finished_at_utc"):
        if key in kv:
            dt = parse_dt(kv.get(key))
            if dt:
                return key, dt
    return None, None


def collect_duration_metrics_from_kv(stage: str, path: Path, kv: dict[str, str]) -> list[dict[str, Any]]:
    metrics: list[dict[str, Any]] = []
    for k, v in kv.items():
        lk = k.lower()
        if (
            lk.endswith("_sec")
            or lk.endswith("_secs")
            or lk.endswith("_seconds")
            or "duration_sec" in lk
            or "elapsed_sec" in lk
            or "wall_clock_sec" in lk
            or "time_span_sec" in lk
        ):
            val = as_float(v, -1)
            if val >= 0:
                metrics.append({
                    "stage": stage,
                    "source": str(path),
                    "metric": k,
                    "seconds": val,
                    "human": seconds_to_human(val),
                })
    return metrics


def walk_duration_json(obj: Any, prefix: str = "") -> list[tuple[str, float]]:
    found: list[tuple[str, float]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            lk = str(k).lower()
            if isinstance(v, (int, float)) and (
                lk.endswith("_sec")
                or lk.endswith("_secs")
                or lk.endswith("_seconds")
                or "duration_sec" in lk
                or "elapsed_sec" in lk
                or "wall_clock_sec" in lk
                or "time_span_sec" in lk
            ):
                found.append((key, float(v)))
            elif isinstance(v, (dict, list)):
                found.extend(walk_duration_json(v, key))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            found.extend(walk_duration_json(v, f"{prefix}[{i}]"))
    return found


def collect_duration_metrics_from_json(stage: str, path: Path) -> list[dict[str, Any]]:
    if not path.exists() or not path.is_file() or path.stat().st_size == 0:
        return []
    try:
        obj = read_json(path)
    except Exception:
        return []
    out = []
    for key, sec in walk_duration_json(obj):
        if sec >= 0:
            out.append({
                "stage": stage,
                "source": str(path),
                "metric": key,
                "seconds": sec,
                "human": seconds_to_human(sec),
            })
    return out


@dataclass
class EvidenceFile:
    stage: str
    path: Path
    required: bool = True


def build_evidence_files(
    *,
    m17c_run_dir: Path,
    plan_dir: Path,
    i5_dir: Path,
    m18_run_dir: Path,
) -> list[EvidenceFile]:
    checks_dir = m17c_run_dir / "checks"
    m18_checks = m18_run_dir / "checks"
    m18_outputs = m18_run_dir / "outputs"

    return [
        EvidenceFile("I1_incremental_plan_check", plan_dir / "M17_INCREMENTAL_PLAN_CHECK.txt"),
        EvidenceFile("I1_incremental_plan_acceptance", checks_dir / "M17_INCREMENTAL_I1_PLAN_ACCEPTANCE.txt"),
        EvidenceFile("I2_pipeline_check", plan_dir / "M17_INCREMENTAL_I2_PIPELINE_CHECK.txt"),
        EvidenceFile("I2_pipeline_acceptance", checks_dir / "M17_INCREMENTAL_I2_PLAN_ACCEPTANCE.txt"),
        EvidenceFile("I3_postprocess_check", plan_dir / "M17_INCREMENTAL_I3_POSTPROCESS_CHECK.txt"),
        EvidenceFile("I3_postprocess_acceptance", checks_dir / "M17_INCREMENTAL_I3_POSTPROCESS_ACCEPTANCE.txt"),
        EvidenceFile("I4_m18_refresh_check", plan_dir / "M17_INCREMENTAL_I4_M18_REFRESH_CHECK.txt"),
        EvidenceFile("I4_m18_refresh_acceptance", checks_dir / "M17_INCREMENTAL_I4_M18_REFRESH_ACCEPTANCE.txt"),
        EvidenceFile("I4B_m18_repair_acceptance", checks_dir / "M17_INCREMENTAL_I4B_M18_REPAIR_ACCEPTANCE.txt"),
        EvidenceFile("I5_timing_finalizer_check", i5_dir / "M17_INCREMENTAL_I5_TIMING_FINALIZER_CHECK.txt"),
        EvidenceFile("I5_timing_finalizer_acceptance", checks_dir / "M17_INCREMENTAL_I5_TIMING_FINALIZER_ACCEPTANCE.txt"),
        EvidenceFile("incremental_mode_final_acceptance", checks_dir / "M17_INCREMENTAL_MODE_FINAL_ACCEPTANCE.txt"),

        EvidenceFile("M18_input_precheck", m18_checks / "M18_INPUT_PRECHECK.txt"),
        EvidenceFile("M18_lifetime_tracker", m18_checks / "M18_LIFETIME_TRACKER_CHECK.txt"),
        EvidenceFile("M18_convergence_report", m18_checks / "M18_CONVERGENCE_REPORT_CHECK.txt"),
        EvidenceFile("M18_timing_evidence", m18_checks / "M18_TIMING_EVIDENCE_INTEGRATION_CHECK.txt"),
        EvidenceFile("M18_acceptance", m18_checks / "M18_ACCEPTANCE.txt"),

        EvidenceFile("M18_lifetime_summary_json", m18_outputs / "m18_lifetime_tracker_summary.json", required=False),
        EvidenceFile("M18_timing_summary_json", m18_outputs / "m18_timing_evidence_summary.json", required=False),
        EvidenceFile("M18_convergence_json", m18_outputs / "convergence_baseline_report.json", required=False),
        EvidenceFile("I5_summary_json", i5_dir / "m17_incremental_i5_timing_finalizer_summary.json", required=False),
    ]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--m17c-run-dir", required=True)
    ap.add_argument("--target-window-id", required=True)
    ap.add_argument("--plan-dir", required=True)
    ap.add_argument("--i5-dir", required=True)
    ap.add_argument("--m18-run-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--manual-gap-threshold-sec", type=int, default=1800)
    args = ap.parse_args()

    m17c_run_dir = Path(args.m17c_run_dir)
    plan_dir = Path(args.plan_dir)
    i5_dir = Path(args.i5_dir)
    m18_run_dir = Path(args.m18_run_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    evidence_files = build_evidence_files(
        m17c_run_dir=m17c_run_dir,
        plan_dir=plan_dir,
        i5_dir=i5_dir,
        m18_run_dir=m18_run_dir,
    )

    evidence_records: list[dict[str, Any]] = []
    duration_metrics: list[dict[str, Any]] = []
    missing_required: list[str] = []

    for ef in evidence_files:
        exists = ef.path.exists() and ef.path.is_file() and ef.path.stat().st_size > 0
        if ef.required and not exists:
            missing_required.append(str(ef.path))

        record: dict[str, Any] = {
            "stage": ef.stage,
            "path": str(ef.path),
            "required": ef.required,
            "exists": exists,
            "status_key": None,
            "status": "MISSING" if not exists else "UNKNOWN",
            "timestamp_key": None,
            "timestamp_utc": None,
        }

        if exists and ef.path.suffix.lower() == ".txt":
            kv = parse_kv_text(ef.path)
            status_key, status = parse_status(ef.path)
            ts_key, ts = find_timestamp(kv)
            record.update({
                "status_key": status_key,
                "status": status,
                "timestamp_key": ts_key,
                "timestamp_utc": dt_to_z(ts),
            })
            duration_metrics.extend(collect_duration_metrics_from_kv(ef.stage, ef.path, kv))

        elif exists and ef.path.suffix.lower() == ".json":
            try:
                obj = read_json(ef.path)
                ts = parse_dt(str(obj.get("generated_at_utc") or obj.get("created_at_utc") or ""))
                record.update({
                    "status_key": "json.status",
                    "status": str(obj.get("status", "JSON_PRESENT")),
                    "timestamp_key": "generated_at_utc" if obj.get("generated_at_utc") else None,
                    "timestamp_utc": dt_to_z(ts),
                })
            except Exception:
                record.update({"status": "JSON_PARSE_FAILED"})
            duration_metrics.extend(collect_duration_metrics_from_json(ef.stage, ef.path))

        evidence_records.append(record)

    # Load plan / I5 summary for window-based saving.
    plan_path = plan_dir / "m17_incremental_plan.json"
    plan = read_json(plan_path) if plan_path.exists() else {}
    plan_summary = plan.get("summary", {}) if isinstance(plan, dict) else {}

    i5_summary_path = i5_dir / "m17_incremental_i5_timing_finalizer_summary.json"
    i5_summary = read_json(i5_summary_path) if i5_summary_path.exists() else {}

    window_count = as_int(plan.get("window_count") if isinstance(plan, dict) else 0)
    run_window_count = as_int(plan_summary.get("run_window_count"))
    skip_window_count = as_int(plan_summary.get("skip_window_count"))
    repair_window_count = as_int(plan_summary.get("repair_window_count"))
    blocked_window_count = as_int(plan_summary.get("blocked_window_count"))

    if not window_count and isinstance(i5_summary, dict):
        window_count = as_int(i5_summary.get("plan", {}).get("window_count"))
        run_window_count = as_int(i5_summary.get("plan", {}).get("run_window_count"))
        skip_window_count = as_int(i5_summary.get("plan", {}).get("skip_window_count"))
        repair_window_count = as_int(i5_summary.get("plan", {}).get("repair_window_count"))
        blocked_window_count = as_int(i5_summary.get("plan", {}).get("blocked_window_count"))

    incremental_compute_windows = run_window_count + repair_window_count
    full_compute_windows = window_count
    saved_window_count = max(0, full_compute_windows - incremental_compute_windows)
    skip_ratio = saved_window_count / full_compute_windows if full_compute_windows else 0.0

    # Timestamp evidence.
    timestamped = []
    for r in evidence_records:
        dt = parse_dt(r.get("timestamp_utc"))
        if dt:
            timestamped.append({
                "stage": r["stage"],
                "timestamp_utc": dt_to_z(dt),
                "datetime": dt,
                "path": r["path"],
                "status": r["status"],
            })
    timestamped.sort(key=lambda x: x["datetime"])

    timestamp_span_sec: float | None = None
    if len(timestamped) >= 2:
        timestamp_span_sec = (timestamped[-1]["datetime"] - timestamped[0]["datetime"]).total_seconds()

    gaps = []
    clusters: list[list[dict[str, Any]]] = []
    current_cluster: list[dict[str, Any]] = []
    prev = None
    for rec in timestamped:
        if prev is None:
            current_cluster = [rec]
        else:
            gap_sec = (rec["datetime"] - prev["datetime"]).total_seconds()
            gaps.append({
                "from_stage": prev["stage"],
                "to_stage": rec["stage"],
                "from_timestamp_utc": dt_to_z(prev["datetime"]),
                "to_timestamp_utc": dt_to_z(rec["datetime"]),
                "gap_sec": gap_sec,
                "gap_human": seconds_to_human(gap_sec),
                "classified_as_manual_or_external_gap": gap_sec > args.manual_gap_threshold_sec,
            })
            if gap_sec > args.manual_gap_threshold_sec:
                clusters.append(current_cluster)
                current_cluster = [rec]
            else:
                current_cluster.append(rec)
        prev = rec
    if current_cluster:
        clusters.append(current_cluster)

    contiguous_cluster_spans = []
    contiguous_total_sec = 0.0
    for c in clusters:
        if not c:
            continue
        span = (c[-1]["datetime"] - c[0]["datetime"]).total_seconds() if len(c) >= 2 else 0.0
        contiguous_total_sec += span
        contiguous_cluster_spans.append({
            "start_stage": c[0]["stage"],
            "end_stage": c[-1]["stage"],
            "start_timestamp_utc": dt_to_z(c[0]["datetime"]),
            "end_timestamp_utc": dt_to_z(c[-1]["datetime"]),
            "span_sec": span,
            "span_human": seconds_to_human(span),
            "event_count": len(c),
        })

    # Known explicit durations if files expose duration_sec.
    # Avoid double counting arbitrary nested duration metrics; still report them.
    total_duration_candidates = [
        m for m in duration_metrics
        if any(token in m["metric"].lower() for token in ("total", "pipeline", "wall_clock", "elapsed"))
    ]
    best_explicit_duration_sec = None
    if total_duration_candidates:
        best_explicit_duration_sec = max(m["seconds"] for m in total_duration_candidates)

    # Advisor proxy:
    # Prefer explicit total duration when present; otherwise use contiguous timestamp span with manual gaps removed.
    if best_explicit_duration_sec is not None and best_explicit_duration_sec > 0:
        duration_proxy_sec = best_explicit_duration_sec
        duration_proxy_source = "explicit_duration_metric"
    elif contiguous_total_sec > 0:
        duration_proxy_sec = contiguous_total_sec
        duration_proxy_source = "timestamp_contiguous_span_manual_gaps_removed"
    else:
        duration_proxy_sec = None
        duration_proxy_source = "insufficient_duration_evidence"

    # Frequency advisor: advisor only, not scheduler default.
    final_acceptance = next((r for r in evidence_records if r["stage"] == "incremental_mode_final_acceptance"), {})
    m18_acceptance = next((r for r in evidence_records if r["stage"] == "M18_acceptance"), {})
    final_ok = final_acceptance.get("status") == "PASS"
    m18_ok = m18_acceptance.get("status") == "PASS"
    all_required_present = not missing_required

    if not all_required_present:
        advisor_label = "blocked_missing_required_evidence"
        minimum_safe_gap_sec = None
        advisor_reason = "Some required check/acceptance files are missing."
    elif not (final_ok and m18_ok):
        advisor_label = "blocked_not_fully_accepted"
        minimum_safe_gap_sec = None
        advisor_reason = "M17 incremental final acceptance or M18 acceptance is not PASS."
    elif duration_proxy_sec is None:
        advisor_label = "bootstrap_collect_wall_clock"
        minimum_safe_gap_sec = None
        advisor_reason = "No explicit duration or sufficient timestamp span found; collect more automatic runs."
    else:
        # Use 1.5x margin and round up to 5 min. This is an advisor only.
        minimum_safe_gap_sec = int(math.ceil((duration_proxy_sec * 1.5) / 300.0) * 300)
        if duration_proxy_sec <= 1800:
            advisor_label = "high_frequency_candidate"
        elif duration_proxy_sec <= 3600:
            advisor_label = "one_hour_candidate"
        elif duration_proxy_sec <= 7200:
            advisor_label = "two_hour_candidate"
        else:
            advisor_label = "three_hour_or_backoff_candidate"
        advisor_reason = "Advisor based on current duration proxy; do not treat as fixed default frequency."

    slowest_duration_metrics = sorted(duration_metrics, key=lambda x: x["seconds"], reverse=True)[:20]

    report = {
        "schema": "s3.m17c.automation_duration_summary.v1",
        "generated_at_utc": utc_now(),
        "status": "PASS" if all_required_present and final_ok and m18_ok else "FAIL",
        "target_window_id": args.target_window_id,
        "m17c_run_dir": str(m17c_run_dir),
        "m18_run_dir": str(m18_run_dir),
        "out_dir": str(out_dir),
        "window_based_saving": {
            "full_compute_windows": full_compute_windows,
            "incremental_compute_windows": incremental_compute_windows,
            "run_window_count": run_window_count,
            "skip_window_count": skip_window_count,
            "repair_window_count": repair_window_count,
            "blocked_window_count": blocked_window_count,
            "saved_window_count": saved_window_count,
            "skip_ratio": round(skip_ratio, 6),
            "estimated_compute_reduction_ratio": round(skip_ratio, 6),
            "interpretation": "recompute_avoidance_ratio_not_wall_clock_duration",
        },
        "timestamp_evidence": {
            "timestamp_event_count": len(timestamped),
            "first_timestamp_utc": dt_to_z(timestamped[0]["datetime"]) if timestamped else None,
            "last_timestamp_utc": dt_to_z(timestamped[-1]["datetime"]) if timestamped else None,
            "raw_timestamp_span_sec": timestamp_span_sec,
            "raw_timestamp_span_human": seconds_to_human(timestamp_span_sec),
            "manual_gap_threshold_sec": args.manual_gap_threshold_sec,
            "contiguous_span_manual_gaps_removed_sec": contiguous_total_sec,
            "contiguous_span_manual_gaps_removed_human": seconds_to_human(contiguous_total_sec),
            "contains_manual_or_external_gaps": any(g["classified_as_manual_or_external_gap"] for g in gaps),
            "gaps": gaps,
            "contiguous_clusters": contiguous_cluster_spans,
            "note": "Timestamps are completion/checkpoint evidence. They are not equivalent to precise stage start/end timing unless stage duration metrics are present.",
        },
        "explicit_duration_metrics": {
            "metric_count": len(duration_metrics),
            "best_explicit_duration_sec": best_explicit_duration_sec,
            "best_explicit_duration_human": seconds_to_human(best_explicit_duration_sec),
            "slowest_metrics": slowest_duration_metrics,
        },
        "duration_proxy_for_advisor": {
            "duration_proxy_sec": duration_proxy_sec,
            "duration_proxy_human": seconds_to_human(duration_proxy_sec),
            "duration_proxy_source": duration_proxy_source,
        },
        "frequency_advisor": {
            "advisor_label": advisor_label,
            "minimum_safe_gap_sec": minimum_safe_gap_sec,
            "minimum_safe_gap_human": seconds_to_human(minimum_safe_gap_sec),
            "default_frequency_policy": "none_event_driven_guarded",
            "reason": advisor_reason,
            "important_note": "Do not hard-code 1h/2h/3h yet. Use readiness gate plus lock, then refine after multiple automatic samples.",
        },
        "acceptance_snapshot": {
            "incremental_mode_final_acceptance": final_acceptance.get("status"),
            "m18_acceptance": m18_acceptance.get("status"),
            "missing_required_files": missing_required,
        },
        "evidence_records": [
            {k: v for k, v in r.items() if k != "datetime"} for r in evidence_records
        ],
        "semantic_boundary": {
            "mapping_strength": "weak",
            "strong_causal_claim_allowed": False,
            "accepted_object_set_available": False,
            "do_not_interpret_export_time_as_validation_start": True,
        },
        "next_batch": "J2_READINESS_GATE_OR_AUTO_ONCE_ORCHESTRATOR",
    }

    write_json(out_dir / "automation_duration_summary.json", report)

    md = []
    md.append("# M17C / M18 Automation Duration Summary")
    md.append("")
    md.append(f"- generated_at_utc: `{report['generated_at_utc']}`")
    md.append(f"- status: `{report['status']}`")
    md.append(f"- target_window_id: `{args.target_window_id}`")
    md.append("")
    md.append("## 1. Window-based recompute avoidance")
    md.append("")
    for k, v in report["window_based_saving"].items():
        md.append(f"- {k}: `{v}`")
    md.append("")
    md.append("## 2. Timestamp evidence")
    md.append("")
    ts = report["timestamp_evidence"]
    for k in [
        "timestamp_event_count",
        "first_timestamp_utc",
        "last_timestamp_utc",
        "raw_timestamp_span_sec",
        "raw_timestamp_span_human",
        "contiguous_span_manual_gaps_removed_sec",
        "contiguous_span_manual_gaps_removed_human",
        "contains_manual_or_external_gaps",
    ]:
        md.append(f"- {k}: `{ts.get(k)}`")
    md.append("")
    md.append("## 3. Explicit duration metrics")
    md.append("")
    edm = report["explicit_duration_metrics"]
    md.append(f"- metric_count: `{edm['metric_count']}`")
    md.append(f"- best_explicit_duration_sec: `{edm['best_explicit_duration_sec']}`")
    md.append(f"- best_explicit_duration_human: `{edm['best_explicit_duration_human']}`")
    md.append("")
    md.append("## 4. Frequency advisor")
    md.append("")
    for k, v in report["frequency_advisor"].items():
        md.append(f"- {k}: `{v}`")
    md.append("")
    md.append("## 5. Semantic boundary")
    md.append("")
    for k, v in report["semantic_boundary"].items():
        md.append(f"- {k}: `{v}`")
    md.append("")
    md.append(f"next_batch: `{report['next_batch']}`")
    (out_dir / "automation_duration_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    txt = [
        f"M17C_AUTOMATION_DURATION_SUMMARY={report['status']}",
        f"generated_at_utc = {report['generated_at_utc']}",
        f"target_window_id = {args.target_window_id}",
        f"full_compute_windows = {full_compute_windows}",
        f"incremental_compute_windows = {incremental_compute_windows}",
        f"saved_window_count = {saved_window_count}",
        f"skip_ratio = {round(skip_ratio, 6)}",
        f"estimated_compute_reduction_ratio = {round(skip_ratio, 6)}",
        f"timestamp_event_count = {len(timestamped)}",
        f"raw_timestamp_span_sec = {timestamp_span_sec}",
        f"raw_timestamp_span_human = {seconds_to_human(timestamp_span_sec)}",
        f"contiguous_span_manual_gaps_removed_sec = {contiguous_total_sec}",
        f"contiguous_span_manual_gaps_removed_human = {seconds_to_human(contiguous_total_sec)}",
        f"explicit_duration_metric_count = {len(duration_metrics)}",
        f"duration_proxy_sec = {duration_proxy_sec}",
        f"duration_proxy_human = {seconds_to_human(duration_proxy_sec)}",
        f"duration_proxy_source = {duration_proxy_source}",
        f"frequency_advisor_label = {advisor_label}",
        f"minimum_safe_gap_sec = {minimum_safe_gap_sec}",
        f"minimum_safe_gap_human = {seconds_to_human(minimum_safe_gap_sec)}",
        "default_frequency_policy = none_event_driven_guarded",
        "mapping_strength = weak",
        "strong_causal_claim_allowed = False",
        f"summary_json = {out_dir / 'automation_duration_summary.json'}",
        f"summary_md = {out_dir / 'automation_duration_summary.md'}",
        f"next_batch = {report['next_batch']}",
    ]

    (out_dir / "M17C_AUTOMATION_DURATION_SUMMARY_CHECK.txt").write_text("\n".join(txt) + "\n", encoding="utf-8")
    print("\n".join(txt))

    if report["status"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
