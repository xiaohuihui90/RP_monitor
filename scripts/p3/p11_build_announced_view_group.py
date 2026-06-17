#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def parse_time(s: str | None):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def build_probe_root(records: list[dict[str, Any]]) -> str:
    rows = []
    for r in records:
        rows.append("|".join([
            str(r.get("pp_id")),
            str(r.get("notification_uri")),
            str(r.get("fetch_status")),
            str(r.get("session_id")),
            str(r.get("serial")),
            str(r.get("notification_digest")),
            str(r.get("snapshot_hash")),
            str(r.get("delta_hash_chain_root")),
        ]))
    material = "\n".join(sorted(rows)).encode("utf-8")
    return "sha256:" + hashlib.sha256(material).hexdigest()


def pair_name(a: str, b: str) -> str:
    return f"{a}_vs_{b}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--group-id", required=True)
    ap.add_argument("--group-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--required-probes", default="probe-cd,probe-bj,probe-sg")
    ap.add_argument("--pp-scope", default="arin,ripe,apnic")
    args = ap.parse_args()

    group_id = args.group_id
    group_dir = Path(args.group_dir)
    out_dir = Path(args.out_dir)

    required_probes = [x.strip() for x in args.required_probes.split(",") if x.strip()]
    pp_scope = [x.strip() for x in args.pp_scope.split(",") if x.strip()]

    checks_dir = out_dir / "checks"
    manifests_dir = out_dir / "manifests"
    outputs_dir = out_dir / "outputs"
    diffs_dir = out_dir / "diffs"

    for d in [checks_dir, manifests_dir, outputs_dir, diffs_dir]:
        d.mkdir(parents=True, exist_ok=True)

    blockers: list[str] = []
    warnings: list[str] = []

    records_by_probe: dict[str, list[dict[str, Any]]] = {}
    summaries_by_probe: dict[str, dict[str, Any]] = {}

    for probe in required_probes:
        pdir = group_dir / probe
        rec_path = pdir / "announced_view_records.jsonl"
        sum_path = pdir / "announced_view_probe_summary.json"

        if not rec_path.exists():
            blockers.append(f"missing_records:{probe}:{rec_path}")
            continue
        if not sum_path.exists():
            blockers.append(f"missing_summary:{probe}:{sum_path}")
            continue

        records = read_jsonl(rec_path)
        summary = read_json(sum_path)

        records_by_probe[probe] = records
        summaries_by_probe[probe] = summary

        if summary.get("snapshot_group_id") != group_id:
            blockers.append(f"group_id_mismatch:{probe}:{summary.get('snapshot_group_id')}")

        if summary.get("success_count", 0) < len(pp_scope):
            warnings.append(f"{probe}:success_count_less_than_pp_scope")

    received_probes = sorted(records_by_probe.keys())
    announced_view_group_complete = sorted(received_probes) == sorted(required_probes)

    if not announced_view_group_complete:
        blockers.append("announced_view_group_incomplete")

    probe_roots = {
        probe: build_probe_root(records)
        for probe, records in records_by_probe.items()
    }

    pp_maps: dict[str, dict[str, dict[str, Any]]] = {}
    for probe, records in records_by_probe.items():
        pp_maps[probe] = {r.get("pp_id"): r for r in records}

    pp_summary: dict[str, Any] = {}
    fields = [
        "fetch_status",
        "session_id",
        "serial",
        "notification_digest",
        "snapshot_hash",
        "delta_hash_chain_root",
    ]

    for pp in pp_scope:
        values_by_probe = {}
        field_aligned = {}

        for field in fields:
            vals = {}
            for probe in required_probes:
                rec = pp_maps.get(probe, {}).get(pp)
                vals[probe] = rec.get(field) if rec else None

            non_null = set(v for v in vals.values() if v is not None)
            field_aligned[field] = (
                len(non_null) <= 1
                and all(v is not None for v in vals.values())
            )
            values_by_probe[field] = vals

        strict_aligned = (
            announced_view_group_complete
            and all(field_aligned.values())
            and all(
                (pp_maps.get(probe, {}).get(pp) or {}).get("fetch_status") == "success"
                for probe in required_probes
            )
        )

        semantic_aligned = (
            announced_view_group_complete
            and field_aligned.get("fetch_status", False)
            and field_aligned.get("session_id", False)
            and all(
                (pp_maps.get(probe, {}).get(pp) or {}).get("fetch_status") == "success"
                for probe in required_probes
            )
        )

        pp_summary[pp] = {
            "strict_aligned": strict_aligned,
            "semantic_aligned": semantic_aligned,
            "field_aligned": field_aligned,
            "values_by_probe": values_by_probe,
        }

    pair_summary: dict[str, Any] = {}
    all_pairwise_diff_count = 0

    probes = sorted(records_by_probe.keys())

    for i in range(len(probes)):
        for j in range(i + 1, len(probes)):
            a = probes[i]
            b = probes[j]
            diff_by_pp: dict[str, list[str]] = {}
            diff_count = 0

            for pp in pp_scope:
                ar = pp_maps.get(a, {}).get(pp)
                br = pp_maps.get(b, {}).get(pp)

                field_diffs = []
                for field in fields:
                    av = ar.get(field) if ar else None
                    bv = br.get(field) if br else None
                    if av != bv:
                        field_diffs.append(field)

                if field_diffs:
                    diff_by_pp[pp] = field_diffs
                    diff_count += 1

            all_pairwise_diff_count += diff_count

            pair_summary[pair_name(a, b)] = {
                "pp_diff_count": diff_count,
                "field_diff_by_pp": diff_by_pp,
                "jaccard_similarity": 1.0 if diff_count == 0 else max(0.0, 1.0 - diff_count / max(1, len(pp_scope))),
            }

    strict_announced_view_aligned = (
        announced_view_group_complete
        and all(pp_summary.get(pp, {}).get("strict_aligned") is True for pp in pp_scope)
        and all_pairwise_diff_count == 0
    )

    semantic_announced_view_aligned = (
        announced_view_group_complete
        and all(pp_summary.get(pp, {}).get("semantic_aligned") is True for pp in pp_scope)
    )

    started_times = []
    finished_times = []

    for s in summaries_by_probe.values():
        st = parse_time(s.get("started_at_utc"))
        ft = parse_time(s.get("finished_at_utc"))
        if st:
            started_times.append(st)
        if ft:
            finished_times.append(ft)

    all_times = started_times + finished_times

    generated_time_min = min(all_times).isoformat() if all_times else None
    generated_time_max = max(all_times).isoformat() if all_times else None

    generated_time_skew_seconds = None
    if all_times:
        generated_time_skew_seconds = int((max(all_times) - min(all_times)).total_seconds())

    if generated_time_skew_seconds is not None and generated_time_skew_seconds <= 600:
        window_mapping_level = "strong"
    else:
        window_mapping_level = "weak_or_unknown"

    manifest = {
        "schema": "s3.stage3.m15.announced_view_group_manifest.v1",
        "created_at_utc": utc_now(),
        "snapshot_group_id": group_id,
        "collection_mode": "retrofit_or_diagnostic",
        "required_probes": required_probes,
        "received_probes": received_probes,
        "announced_view_group_complete": announced_view_group_complete,
        "pp_scope": pp_scope,
        "generated_time_min": generated_time_min,
        "generated_time_max": generated_time_max,
        "generated_time_skew_seconds": generated_time_skew_seconds,
        "window_mapping_level": window_mapping_level,
        "strict_announced_view_aligned": strict_announced_view_aligned,
        "semantic_announced_view_aligned": semantic_announced_view_aligned,
        "probe_roots": probe_roots,
        "pp_summary": pp_summary,
        "warnings": warnings,
        "blockers": blockers,
    }

    diff = {
        "schema": "s3.stage3.m15.announced_view_pairwise_diff.v1",
        "created_at_utc": utc_now(),
        "snapshot_group_id": group_id,
        "collection_mode": "retrofit_or_diagnostic",
        "all_pairwise_diff_count": all_pairwise_diff_count,
        "strict_announced_view_aligned": strict_announced_view_aligned,
        "semantic_announced_view_aligned": semantic_announced_view_aligned,
        "pair_summary": pair_summary,
    }

    write_json(outputs_dir / "announced_view_group_manifest.json", manifest)
    write_json(diffs_dir / "announced_view_pairwise_diff.json", diff)

    acceptance = len(blockers) == 0

    acceptance_text = f"""P11_C_ANNOUNCED_VIEW_GROUP=DONE

created_at_utc = {utc_now()}

snapshot_group_id = {group_id}
collection_mode = retrofit_or_diagnostic

received_probes = {received_probes}
announced_view_group_complete = {announced_view_group_complete}

pp_scope = {pp_scope}

generated_time_min = {generated_time_min}
generated_time_max = {generated_time_max}
generated_time_skew_seconds = {generated_time_skew_seconds}
window_mapping_level = {window_mapping_level}

strict_announced_view_aligned = {strict_announced_view_aligned}
semantic_announced_view_aligned = {semantic_announced_view_aligned}
all_pairwise_diff_count = {all_pairwise_diff_count}

warnings = {warnings}
blockers = {blockers}

runtime_changes:
  collector_main_service_restarted = False
  probe_restarted = False
  new_validator_installed = False
  bgp_data_loaded = False
  cron_enabled = False

outputs:
  {outputs_dir / "announced_view_group_manifest.json"}
  {diffs_dir / "announced_view_pairwise_diff.json"}

next_batch:
  Batch 3 / A3 / P11-D three_layer_final_gate

P11_C_acceptance = {acceptance}
"""

    (checks_dir / "P11_C_announced_view_group_acceptance.txt").write_text(
        acceptance_text,
        encoding="utf-8",
    )

    run_manifest = {
        "schema": "s3.stage3.m15.p11_c_announced_view_run_manifest.v1",
        "created_at_utc": utc_now(),
        "snapshot_group_id": group_id,
        "p11_c_id": out_dir.name,
        "p11_c_dir": str(out_dir),
        "group_dir": str(group_dir),
        "announced_view_group_manifest": str(outputs_dir / "announced_view_group_manifest.json"),
        "announced_view_pairwise_diff": str(diffs_dir / "announced_view_pairwise_diff.json"),
        "announced_view_group_complete": announced_view_group_complete,
        "strict_announced_view_aligned": strict_announced_view_aligned,
        "semantic_announced_view_aligned": semantic_announced_view_aligned,
        "all_pairwise_diff_count": all_pairwise_diff_count,
        "window_mapping_level": window_mapping_level,
        "generated_time_skew_seconds": generated_time_skew_seconds,
        "warnings": warnings,
        "blockers": blockers,
        "P11_C_acceptance": acceptance,
    }

    write_json(manifests_dir / "P11_C_announced_view_run_manifest.json", run_manifest)

    print(acceptance_text)

    if not acceptance:
        raise SystemExit("[BLOCKED] P11-C group acceptance is False")


if __name__ == "__main__":
    main()
