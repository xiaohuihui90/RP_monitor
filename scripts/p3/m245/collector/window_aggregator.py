#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scripts.p3.m245.common.m245_hash import sha256_file
from scripts.p3.m245.common.m245_jsonl import read_jsonl, write_jsonl, write_json
from scripts.p3.m245.common.m245_paths import collector_window_dir, ensure_standard_dirs


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def copy_probe_inputs(probe_id: str, run_dir: Path, dest_inputs_dir: Path) -> dict[str, Any]:
    dest = dest_inputs_dir / probe_id
    dest.mkdir(parents=True, exist_ok=True)

    copied = []
    for rel in [
        "indexes/advertised_view_records.jsonl",
        "indexes/object_view_light_records.jsonl",
        "indexes/validation_output_light_records.jsonl",
        "indexes/validator_context_records.jsonl",
        "outputs/m245_probe_window_summary.json",
        "checks/M245_probe_window_check.txt",
        "run_manifest.json",
    ]:
        src = run_dir / rel
        if src.exists():
            dst = dest / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            copied.append(str(dst))

    return {
        "probe_id": probe_id,
        "source_run_dir": str(run_dir),
        "collector_input_dir": str(dest),
        "copied_files": copied,
    }


def load_probe_summary(run_dir: Path) -> dict[str, Any]:
    p = run_dir / "outputs" / "m245_probe_window_summary.json"
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def load_probe_check_status(run_dir: Path) -> dict[str, Any]:
    p = run_dir / "checks" / "M245_probe_window_check.txt"
    item = {
        "status": "MISSING",
        "window_id": None,
        "probe_id": None,
        "vrp_count": None,
        "object_count_total": None,
        "manifest_count_total": None,
    }
    if not p.exists():
        return item

    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("M245_PROBE_WINDOW="):
            item["status"] = line.split("=", 1)[1].strip()
        elif line.startswith("window_id ="):
            item["window_id"] = line.split("=", 1)[1].strip()
        elif line.startswith("probe_id ="):
            item["probe_id"] = line.split("=", 1)[1].strip()
        elif line.startswith("vrp_count ="):
            item["vrp_count"] = line.split("=", 1)[1].strip()
        elif line.startswith("object_count_total ="):
            item["object_count_total"] = line.split("=", 1)[1].strip()
        elif line.startswith("manifest_count_total ="):
            item["manifest_count_total"] = line.split("=", 1)[1].strip()
    return item


def read_layer_records(run_dir: Path, filename: str) -> list[dict[str, Any]]:
    p = run_dir / "indexes" / filename
    if not p.exists():
        return []
    return list(read_jsonl(p))


def value_relation(values_by_probe: dict[str, Any]) -> str:
    vals = [v for v in values_by_probe.values() if v is not None]
    if not vals:
        return "unknown"
    if len(set(map(str, vals))) == 1:
        return "same"
    return "divergent"


def build_status_matrix(
    window_id: str,
    probe_ids: list[str],
    advertised: list[dict[str, Any]],
    objects: list[dict[str, Any]],
    validation: list[dict[str, Any]],
    probe_checks: dict[str, dict[str, Any]],
    run_mode: str,
    time_alignment_quality: str,
) -> dict[str, Any]:

    # Advertised view: compare per pp_id session/serial/digest/fetch status.
    adv_by_pp = defaultdict(dict)
    for r in advertised:
        pp_id = r.get("pp_id")
        probe_id = r.get("probe_id")
        if pp_id and probe_id:
            adv_by_pp[pp_id][probe_id] = r

    adv_pp_status = {}
    adv_diff_count = 0
    for pp_id, by_probe in sorted(adv_by_pp.items()):
        session = {p: by_probe.get(p, {}).get("session_id") for p in probe_ids}
        serial = {p: by_probe.get(p, {}).get("serial") for p in probe_ids}
        digest = {p: by_probe.get(p, {}).get("notif_digest") for p in probe_ids}
        fetch_status = {p: by_probe.get(p, {}).get("fetch_status") for p in probe_ids}

        pp_status = {
            "session_relation": value_relation(session),
            "serial_relation": value_relation(serial),
            "notif_digest_relation": value_relation(digest),
            "fetch_status_relation": value_relation(fetch_status),
            "session_by_probe": session,
            "serial_by_probe": serial,
            "notif_digest_by_probe": digest,
            "fetch_status_by_probe": fetch_status,
        }

        if any(pp_status[k] == "divergent" for k in [
            "session_relation",
            "serial_relation",
            "notif_digest_relation",
            "fetch_status_relation",
        ]):
            adv_diff_count += 1

        adv_pp_status[pp_id] = pp_status

    # Object view: one light record per probe, pp_id all for now.
    obj_by_probe = {r.get("probe_id"): r for r in objects if r.get("probe_id")}
    object_set_root = {p: obj_by_probe.get(p, {}).get("object_set_root") for p in probe_ids}
    object_count = {p: obj_by_probe.get(p, {}).get("object_count") for p in probe_ids}
    manifest_count = {p: obj_by_probe.get(p, {}).get("manifest_count") for p in probe_ids}
    manifest_root = {p: obj_by_probe.get(p, {}).get("manifest_summary_root") for p in probe_ids}
    cache_dir = {p: obj_by_probe.get(p, {}).get("cache_dir") for p in probe_ids}

    object_status = {
        "object_set_root_relation": value_relation(object_set_root),
        "object_count_relation": value_relation(object_count),
        "manifest_count_relation": value_relation(manifest_count),
        "manifest_summary_root_relation": value_relation(manifest_root),
        "object_set_root_by_probe": object_set_root,
        "object_count_by_probe": object_count,
        "manifest_count_by_probe": manifest_count,
        "manifest_summary_root_by_probe": manifest_root,
        "cache_dir_by_probe": cache_dir,
    }

    object_diff_count = sum(
        1 for k in [
            "object_set_root_relation",
            "object_count_relation",
            "manifest_count_relation",
            "manifest_summary_root_relation",
        ]
        if object_status[k] == "divergent"
    )

    # Validation output.
    val_by_probe = {r.get("probe_id"): r for r in validation if r.get("probe_id")}
    vrp_count = {p: val_by_probe.get(p, {}).get("vrp_count") for p in probe_ids}
    vrp_root = {p: val_by_probe.get(p, {}).get("vrp_root") for p in probe_ids}
    validator_version = {p: val_by_probe.get(p, {}).get("validator_version") for p in probe_ids}
    export_status = {p: val_by_probe.get(p, {}).get("export_status") for p in probe_ids}

    validation_status = {
        "vrp_count_relation": value_relation(vrp_count),
        "vrp_root_relation": value_relation(vrp_root),
        "validator_version_relation": value_relation(validator_version),
        "export_status_relation": value_relation(export_status),
        "vrp_count_by_probe": vrp_count,
        "vrp_root_by_probe": vrp_root,
        "validator_version_by_probe": validator_version,
        "export_status_by_probe": export_status,
    }

    validation_diff_count = sum(
        1 for k in [
            "vrp_count_relation",
            "vrp_root_relation",
            "validator_version_relation",
            "export_status_relation",
        ]
        if validation_status[k] == "divergent"
    )

    # Overall.
    layer_status = {
        "advertised_view": "divergent" if adv_diff_count else "consistent",
        "object_view": "divergent" if object_diff_count else "consistent",
        "validation_output": "divergent" if validation_diff_count else "consistent",
    }

    m25_trigger_required = any(v == "divergent" for v in layer_status.values())

    return {
        "schema": "s3.m245.three_layer_status_matrix.v1",
        "created_at_utc": utc_now(),
        "window_id": window_id,
        "run_mode": run_mode,
        "time_alignment_quality": time_alignment_quality,
        "comparison_strength": "diagnostic_only" if time_alignment_quality != "on_time" else "strict_same_window",
        "probe_ids": probe_ids,
        "probe_checks": probe_checks,
        "layer_status": layer_status,
        "advertised_view": {
            "status": layer_status["advertised_view"],
            "diff_count": adv_diff_count,
            "pp_status": adv_pp_status,
        },
        "object_view": {
            "status": layer_status["object_view"],
            "diff_count": object_diff_count,
            **object_status,
        },
        "validation_output": {
            "status": layer_status["validation_output"],
            "diff_count": validation_diff_count,
            **validation_status,
        },
        "m25_trigger_required": m25_trigger_required,
        "m25_trigger_reason": [
            layer for layer, status in layer_status.items() if status == "divergent"
        ],
        "boundary": "This aggregation may be diagnostic_only for manual/replay runs. Use observed_at_utc and scheduled mode for strict continuous monitoring.",
    }


def artifact_entry(path: Path, artifact_type: str) -> dict[str, Any]:
    return {
        "artifact_type": artifact_type,
        "path": str(path),
        "exists": path.exists(),
        "sha256": sha256_file(path) if path.exists() else None,
        "size_bytes": path.stat().st_size if path.exists() else None,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--window-id", required=True)
    ap.add_argument("--probe-bj-run-dir", required=True)
    ap.add_argument("--probe-cd-run-dir", required=True)
    ap.add_argument("--probe-sg-run-dir", required=True)
    ap.add_argument("--project-dir", default=".")
    ap.add_argument("--run-mode", default="manual_c2_test")
    ap.add_argument("--time-alignment-quality", default="diagnostic_only")
    args = ap.parse_args()

    project_dir = Path(args.project_dir).resolve()
    window_id = args.window_id
    run_dir = collector_window_dir(project_dir, window_id)
    dirs = ensure_standard_dirs(run_dir)

    probe_run_dirs = {
        "probe-bj": Path(args.probe_bj_run_dir).resolve(),
        "probe-cd": Path(args.probe_cd_run_dir).resolve(),
        "probe-sg": Path(args.probe_sg_run_dir).resolve(),
    }

    probe_inputs = {}
    probe_checks = {}
    summaries = {}

    for probe_id, prun in probe_run_dirs.items():
        probe_inputs[probe_id] = copy_probe_inputs(probe_id, prun, dirs["inputs"])
        probe_checks[probe_id] = load_probe_check_status(prun)
        summaries[probe_id] = load_probe_summary(prun)

    advertised = []
    objects = []
    validation = []
    validator_context = []

    for prun in probe_run_dirs.values():
        advertised.extend(read_layer_records(prun, "advertised_view_records.jsonl"))
        objects.extend(read_layer_records(prun, "object_view_light_records.jsonl"))
        validation.extend(read_layer_records(prun, "validation_output_light_records.jsonl"))
        validator_context.extend(read_layer_records(prun, "validator_context_records.jsonl"))

    adv_path = dirs["indexes"] / "merged_advertised_view_records.jsonl"
    obj_path = dirs["indexes"] / "merged_object_view_light_records.jsonl"
    val_path = dirs["indexes"] / "merged_validation_output_light_records.jsonl"
    ctx_path = dirs["indexes"] / "merged_validator_context_records.jsonl"

    write_jsonl(adv_path, advertised)
    write_jsonl(obj_path, objects)
    write_jsonl(val_path, validation)
    write_jsonl(ctx_path, validator_context)

    probe_ids = ["probe-bj", "probe-cd", "probe-sg"]

    status_matrix = build_status_matrix(
        window_id=window_id,
        probe_ids=probe_ids,
        advertised=advertised,
        objects=objects,
        validation=validation,
        probe_checks=probe_checks,
        run_mode=args.run_mode,
        time_alignment_quality=args.time_alignment_quality,
    )

    matrix_path = dirs["outputs"] / "M245_three_layer_status_matrix.json"
    write_json(matrix_path, status_matrix)

    window_summary = {
        "schema": "s3.m245.collector_window_summary.v1",
        "created_at_utc": utc_now(),
        "window_id": window_id,
        "run_id": run_dir.name,
        "run_mode": args.run_mode,
        "time_alignment_quality": args.time_alignment_quality,
        "probe_count": len(probe_ids),
        "record_counts": {
            "advertised_view": len(advertised),
            "object_view_light": len(objects),
            "validation_output_light": len(validation),
            "validator_context": len(validator_context),
        },
        "layer_status": status_matrix["layer_status"],
        "m25_trigger_required": status_matrix["m25_trigger_required"],
        "m25_trigger_reason": status_matrix["m25_trigger_reason"],
        "probe_summaries": summaries,
        "probe_inputs": probe_inputs,
    }

    summary_path = dirs["outputs"] / "M245_window_summary.json"
    write_json(summary_path, window_summary)

    artifacts = [
        artifact_entry(adv_path, "merged_advertised_view_records"),
        artifact_entry(obj_path, "merged_object_view_light_records"),
        artifact_entry(val_path, "merged_validation_output_light_records"),
        artifact_entry(ctx_path, "merged_validator_context_records"),
        artifact_entry(matrix_path, "M245_three_layer_status_matrix"),
        artifact_entry(summary_path, "M245_window_summary"),
    ]

    manifest = {
        "schema": "s3.m245.run_manifest.v1",
        "run_id": run_dir.name,
        "window_id": window_id,
        "created_at_utc": utc_now(),
        "role": "collector",
        "collector_id": "collector-cd",
        "run_mode": args.run_mode,
        "time_alignment_quality": args.time_alignment_quality,
        "probe_run_dirs": {k: str(v) for k, v in probe_run_dirs.items()},
        "artifacts": artifacts,
        "summaries": {
            "window_summary": str(summary_path),
            "status_matrix": str(matrix_path),
        },
        "checks": {
            "window_aggregation_check": str(dirs["checks"] / "M245_window_aggregation_check.txt"),
        },
    }
    write_json(run_dir / "run_manifest.json", manifest)

    hard_fail = []
    for probe_id, item in probe_checks.items():
        if item.get("status") != "PASS":
            hard_fail.append(f"{probe_id}_not_pass:{item.get('status')}")
        if item.get("window_id") != window_id:
            hard_fail.append(f"{probe_id}_window_mismatch:{item.get('window_id')}")

    if len(advertised) < 3:
        hard_fail.append("merged_advertised_view_too_few")
    if len(objects) < 3:
        hard_fail.append("merged_object_view_too_few")
    if len(validation) < 3:
        hard_fail.append("merged_validation_output_too_few")

    status = "PASS" if not hard_fail else "FAIL"

    check_path = dirs["checks"] / "M245_window_aggregation_check.txt"
    with check_path.open("w", encoding="utf-8") as f:
        f.write(f"M245_WINDOW_AGGREGATION={status}\n\n")
        f.write(f"created_at_utc = {utc_now()}\n")
        f.write(f"window_id = {window_id}\n")
        f.write(f"run_dir = {run_dir}\n")
        f.write(f"run_mode = {args.run_mode}\n")
        f.write(f"time_alignment_quality = {args.time_alignment_quality}\n")
        f.write(f"probe_count = {len(probe_ids)}\n")
        f.write(f"merged_advertised_view_records_count = {len(advertised)}\n")
        f.write(f"merged_object_view_light_records_count = {len(objects)}\n")
        f.write(f"merged_validation_output_light_records_count = {len(validation)}\n")
        f.write(f"merged_validator_context_records_count = {len(validator_context)}\n")
        f.write(f"layer_status = {status_matrix['layer_status']}\n")
        f.write(f"m25_trigger_required = {status_matrix['m25_trigger_required']}\n")
        f.write(f"m25_trigger_reason = {status_matrix['m25_trigger_reason']}\n")
        f.write(f"status_matrix_path = {matrix_path}\n")
        f.write(f"summary_path = {summary_path}\n")
        f.write(f"run_manifest_path = {run_dir / 'run_manifest.json'}\n")
        f.write(f"hard_fail = {hard_fail}\n")

    print(f"M245_COLLECTOR_WINDOW_RUN_DIR={run_dir}")
    print(f"M245_WINDOW_AGGREGATION_CHECK={check_path}")
    print(f"M245_WINDOW_AGGREGATION_STATUS={status}")

    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
