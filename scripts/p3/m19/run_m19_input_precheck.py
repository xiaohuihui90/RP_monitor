#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def file_nonempty(path: Path) -> bool:
    return path.exists() and path.is_file() and path.stat().st_size > 0


def line_count(path: Path) -> int:
    if not file_nonempty(path):
        return 0
    n = 0
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for _ in f:
            n += 1
    return n


def parse_status(path: Path, key: str) -> str:
    txt = read_text(path)
    m = re.search(rf"^{re.escape(key)}=(\S+)", txt, re.M)
    return m.group(1) if m else "UNKNOWN"


def parse_kv(path: Path) -> dict[str, str]:
    out = {}
    for line in read_text(path).splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def latest_file(root: Path, pattern: str) -> Path | None:
    files = sorted(root.glob(pattern))
    return files[-1] if files else None


def latest_m18_run(m18_root: Path) -> Path | None:
    candidates = []
    for p in sorted(m18_root.glob("history/*/checks/M18_ACCEPTANCE.txt")):
        if parse_status(p, "M18_ACCEPTANCE") == "PASS":
            candidates.append(p.parent.parent)
    return candidates[-1] if candidates else None


def collect_m17_windows(m17_root: Path) -> list[dict[str, Any]]:
    rows = []
    for out_dir in sorted(m17_root.glob("history/m17_window_*/outputs")):
        window_id = out_dir.parent.name.replace("m17_window_", "")
        diff_records = out_dir / "vrp_entry_diff_records.jsonl"
        diff_summary = out_dir / "vrp_entry_diff_summary.json"
        canonical_manifest = out_dir / "canonical_vrp_manifest.json"
        validator_cycle_records = out_dir / "validator_cycle_records.jsonl"
        effective_input = out_dir / "validator_effective_input_summary.json"
        acceptance = out_dir / "M17_ACCEPTANCE.txt"

        rows.append({
            "window_id": window_id,
            "out_dir": str(out_dir),
            "diff_records": str(diff_records),
            "diff_records_exists": file_nonempty(diff_records),
            "diff_record_count": line_count(diff_records),
            "diff_summary": str(diff_summary),
            "diff_summary_exists": file_nonempty(diff_summary),
            "canonical_manifest": str(canonical_manifest),
            "canonical_manifest_exists": file_nonempty(canonical_manifest),
            "validator_cycle_records": str(validator_cycle_records),
            "validator_cycle_records_exists": file_nonempty(validator_cycle_records),
            "effective_input_summary": str(effective_input),
            "effective_input_summary_exists": file_nonempty(effective_input),
            "m17_acceptance": str(acceptance),
            "m17_acceptance_status": parse_status(acceptance, "M17_ACCEPTANCE"),
        })
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--m17-root", default="data/p3_collector/m17_vrp_entry_diff")
    ap.add_argument("--m18-root", default="data/p3_collector/m18_diff_lifetime")
    ap.add_argument("--m19-root", default="data/p3_collector/m19_roa_to_vrp")
    ap.add_argument("--run-id", default="")
    args = ap.parse_args()

    m17_root = Path(args.m17_root)
    m18_root = Path(args.m18_root)
    m19_root = Path(args.m19_root)

    run_id = args.run_id or f"m19_precheck_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    run_dir = m19_root / "history" / run_id
    input_dir = run_dir / "inputs"
    output_dir = run_dir / "outputs"
    check_dir = run_dir / "checks"
    for d in [input_dir, output_dir, check_dir]:
        d.mkdir(parents=True, exist_ok=True)

    m18_run = latest_m18_run(m18_root)
    blockers = []

    if not m18_run:
        blockers.append("no_pass_m18_run_found")
        m18_acceptance = None
        m18_out = None
    else:
        m18_acceptance = m18_run / "checks" / "M18_ACCEPTANCE.txt"
        m18_out = m18_run / "outputs"

    m19_candidates_with_timing = m18_out / "m19_mapping_candidates_with_timing.jsonl" if m18_out else Path("")
    m19_candidates = m18_out / "m19_mapping_candidates.jsonl" if m18_out else Path("")
    lifetime_with_timing = m18_out / "vrp_diff_lifetime_records_with_timing.jsonl" if m18_out else Path("")
    timing_summary = m18_out / "m18_timing_evidence_summary.json" if m18_out else Path("")
    convergence_report = m18_out / "convergence_baseline_report.json" if m18_out else Path("")

    if not file_nonempty(m19_candidates_with_timing):
        blockers.append("missing_m19_mapping_candidates_with_timing")
    if not file_nonempty(m19_candidates):
        blockers.append("missing_m19_mapping_candidates")

    m17_windows = collect_m17_windows(m17_root)
    ready_m17_windows = [
        w for w in m17_windows
        if w["diff_records_exists"] and w["m17_acceptance_status"] == "PASS"
    ]

    if not ready_m17_windows:
        blockers.append("no_ready_m17_diff_windows")

    m18_kv = parse_kv(m18_acceptance) if m18_acceptance else {}
    mapping_strength = m18_kv.get("mapping_strength", "unknown")
    strong_causal_claim_allowed = m18_kv.get("strong_causal_claim_allowed", "unknown")

    if mapping_strength != "weak":
        blockers.append("mapping_strength_not_weak")
    if strong_causal_claim_allowed != "False":
        blockers.append("strong_causal_claim_not_false")

    inventory = {
        "schema": "s3.m19.input_inventory.v1",
        "generated_at_utc": utc_now(),
        "run_id": run_id,
        "run_dir": str(run_dir),
        "m17_root": str(m17_root),
        "m18_root": str(m18_root),
        "m19_root": str(m19_root),
        "m18": {
            "m18_run_dir": str(m18_run) if m18_run else None,
            "m18_acceptance": str(m18_acceptance) if m18_acceptance else None,
            "m18_acceptance_status": parse_status(m18_acceptance, "M18_ACCEPTANCE") if m18_acceptance else "MISSING",
            "m19_candidates_with_timing": str(m19_candidates_with_timing),
            "m19_candidates_with_timing_exists": file_nonempty(m19_candidates_with_timing),
            "m19_candidates_with_timing_count": line_count(m19_candidates_with_timing),
            "m19_candidates": str(m19_candidates),
            "m19_candidates_exists": file_nonempty(m19_candidates),
            "m19_candidates_count": line_count(m19_candidates),
            "lifetime_with_timing": str(lifetime_with_timing),
            "lifetime_with_timing_exists": file_nonempty(lifetime_with_timing),
            "lifetime_with_timing_count": line_count(lifetime_with_timing),
            "timing_summary": str(timing_summary),
            "timing_summary_exists": file_nonempty(timing_summary),
            "convergence_report": str(convergence_report),
            "convergence_report_exists": file_nonempty(convergence_report),
            "mapping_strength": mapping_strength,
            "strong_causal_claim_allowed": strong_causal_claim_allowed,
        },
        "m17": {
            "window_count": len(m17_windows),
            "ready_window_count": len(ready_m17_windows),
            "total_diff_record_count": sum(w["diff_record_count"] for w in ready_m17_windows),
            "windows": m17_windows,
        },
        "semantic_boundary": {
            "mapping_strength": "weak",
            "strong_causal_claim_allowed": False,
            "accepted_object_set_available": False,
            "m19_claim_scope": "candidate_mapping_and_coverage_only",
        },
        "blockers": blockers,
    }

    status = "PASS" if not blockers else "FAIL"

    write_json(output_dir / "m19_input_inventory.json", inventory)

    # 写 state，方便后续 Batch 1 直接 source
    state_dir = m19_root / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "current_m19_run.env").write_text(
        "\n".join([
            f'export M19_RUN_ID="{run_id}"',
            f'export M19_RUN_DIR="{run_dir}"',
            f'export M19_INPUT_DIR="{input_dir}"',
            f'export M19_OUT_DIR="{output_dir}"',
            f'export M19_CHECK_DIR="{check_dir}"',
            f'export M19_INPUT_INVENTORY="{output_dir / "m19_input_inventory.json"}"',
            f'export M19_M18_RUN_DIR="{m18_run}"',
            f'export M19_CANDIDATES_WITH_TIMING="{m19_candidates_with_timing}"',
            f'export M19_CANDIDATES="{m19_candidates}"',
            "",
        ]),
        encoding="utf-8"
    )

    lines = [
        f"M19_INPUT_PRECHECK={status}",
        f"generated_at_utc = {inventory['generated_at_utc']}",
        f"run_id = {run_id}",
        f"m19_run_dir = {run_dir}",
        f"m18_run_dir = {m18_run}",
        f"m18_acceptance_status = {inventory['m18']['m18_acceptance_status']}",
        f"m19_candidates_with_timing_count = {inventory['m18']['m19_candidates_with_timing_count']}",
        f"m19_candidates_count = {inventory['m18']['m19_candidates_count']}",
        f"m17_window_count = {inventory['m17']['window_count']}",
        f"m17_ready_window_count = {inventory['m17']['ready_window_count']}",
        f"m17_total_diff_record_count = {inventory['m17']['total_diff_record_count']}",
        f"mapping_strength = {mapping_strength}",
        f"strong_causal_claim_allowed = {strong_causal_claim_allowed}",
        f"blockers = {blockers}",
        f"inventory_json = {output_dir / 'm19_input_inventory.json'}",
        "next_batch = M19_BATCH_1_SOURCE_URI_EXTRACTION_DIAG",
    ]

    (check_dir / "M19_INPUT_PRECHECK.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))

    if status != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
