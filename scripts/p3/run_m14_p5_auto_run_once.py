#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import ipaddress
import json
import shutil
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROBES = ["probe-cd", "probe-bj", "probe-sg"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def normalize_asn(asn: Any) -> str:
    if isinstance(asn, int):
        return f"AS{asn}"
    s = str(asn).strip().upper()
    if not s.startswith("AS"):
        s = "AS" + s
    return s


def normalize_prefix(prefix: Any) -> str:
    return str(ipaddress.ip_network(str(prefix).strip(), strict=False))


def canonical_key(roa: dict[str, Any]) -> str:
    tal = str(roa.get("ta", "unknown")).strip().lower()
    asn = normalize_asn(roa.get("asn"))
    prefix = normalize_prefix(roa.get("prefix"))
    max_len = int(roa.get("maxLength"))
    return f"{tal}|{asn}|{prefix}|{max_len}"


def afi_of_prefix(prefix: str) -> str:
    return "ipv6" if ":" in prefix else "ipv4"


def parse_key(key: str) -> tuple[str, str]:
    parts = key.split("|")
    tal = parts[0] if len(parts) > 0 else "unknown"
    prefix = parts[2] if len(parts) > 2 else ""
    return tal, afi_of_prefix(prefix)


def sort_unique_file(src: Path, dst: Path) -> None:
    subprocess.run(
        f"LC_ALL=C sort -u {src} > {dst}",
        shell=True,
        check=True,
        executable="/bin/bash",
    )


def count_lines(path: Path) -> int:
    out = subprocess.check_output(["wc", "-l", str(path)], text=True)
    return int(out.strip().split()[0])


def build_root_from_sorted_keys(sorted_keys: Path) -> str:
    h = hashlib.sha256()
    with sorted_keys.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def breakdown_from_sorted_keys(sorted_keys: Path) -> tuple[dict[str, int], dict[str, int]]:
    tal_counter = Counter()
    afi_counter = Counter()
    with sorted_keys.open("r", encoding="utf-8") as f:
        for line in f:
            key = line.strip()
            if not key:
                continue
            tal, afi = parse_key(key)
            tal_counter[tal] += 1
            afi_counter[afi] += 1
    return dict(sorted(tal_counter.items())), dict(sorted(afi_counter.items()))


def decompress_gzip(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(src, "rb") as fin, dst.open("wb") as fout:
        shutil.copyfileobj(fin, fout)


def normalize_probe(raw_json: Path, probe: str, normalized_dir: Path, work_dir: Path) -> dict[str, Any]:
    raw = read_json(raw_json)
    roas = raw.get("roas", [])
    metadata = raw.get("metadata", {}) if isinstance(raw.get("metadata"), dict) else {}

    keys_tmp = work_dir / f"{probe}.keys.unsorted.txt"
    keys_sorted = work_dir / f"{probe}.keys.sorted.txt"
    index_path = normalized_dir / f"{probe}_vrp_index.jsonl"

    parse_errors = []
    raw_count = 0

    with keys_tmp.open("w", encoding="utf-8") as fout:
        for i, roa in enumerate(roas):
            raw_count += 1
            try:
                fout.write(canonical_key(roa) + "\n")
            except Exception as exc:
                parse_errors.append({"index": i, "error": str(exc), "roa": roa})

    sort_unique_file(keys_tmp, keys_sorted)

    unique_count = count_lines(keys_sorted)
    root = build_root_from_sorted_keys(keys_sorted)
    tal_breakdown, afi_breakdown = breakdown_from_sorted_keys(keys_sorted)

    with keys_sorted.open("r", encoding="utf-8") as fin, index_path.open("w", encoding="utf-8") as fout:
        for line in fin:
            key = line.strip()
            if key:
                fout.write(json.dumps({"canonical_key": key}, ensure_ascii=False) + "\n")

    error_path = normalized_dir / f"{probe}_parse_errors.json"
    write_json(error_path, parse_errors)

    return {
        "probe_id": probe,
        "raw_file": str(raw_json),
        "normalized_file": str(index_path),
        "raw_vrp_count": raw_count,
        "unique_vrp_count": unique_count,
        "parse_error_count": len(parse_errors),
        "warning_count": 0,
        "vrp_root_v1": root,
        "tal_breakdown": tal_breakdown,
        "afi_breakdown": afi_breakdown,
        "metadata": metadata,
    }


def run_lowmem_diff(repo_root: Path, run_dir: Path, sample_limit: int) -> None:
    script = repo_root / "scripts/p3/run_m14a_pairwise_diff_lowmem.py"
    if not script.exists():
        raise FileNotFoundError(f"missing lowmem diff script: {script}")
    subprocess.run(
        [
            "python",
            str(script),
            "--run-dir",
            str(run_dir),
            "--sample-limit",
            str(sample_limit),
        ],
        check=True,
    )


def update_sha256s(run_dir: Path) -> None:
    out = run_dir / "checks/SHA256SUMS.txt"
    rows = []
    for p in sorted(run_dir.rglob("*")):
        if p.is_file() and p != out:
            rows.append((sha256_file(p), str(p.relative_to(run_dir))))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(f"{d}  {rel}\n" for d, rel in rows), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="P5 auto run M14-A lowmem diff from a complete snapshot group")
    ap.add_argument("--group-dir", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--out-root", default="data/p3_collector/m14_vrp_runs")
    ap.add_argument("--sample-limit", type=int, default=100)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    repo_root = Path.cwd()
    group_dir = Path(args.group_dir).resolve()
    group_manifest_path = group_dir / "group_manifest.json"
    group = read_json(group_manifest_path)

    if not group.get("complete"):
        raise RuntimeError("snapshot group is not complete")

    run_dir = (repo_root / args.out_root / args.run_id).resolve()
    if run_dir.exists() and args.force:
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)

    raw_dir = run_dir / "raw_vrps"
    normalized_dir = run_dir / "normalized_vrps"
    summary_dir = run_dir / "summaries"
    diff_dir = run_dir / "diffs"
    verdict_dir = run_dir / "verdicts"
    checks_dir = run_dir / "checks"
    inputs_dir = run_dir / "inputs"
    work_dir = run_dir / "work"

    for d in [raw_dir, normalized_dir, summary_dir, diff_dir, verdict_dir, checks_dir, inputs_dir, work_dir]:
        d.mkdir(parents=True, exist_ok=True)

    shutil.copy2(group_manifest_path, inputs_dir / "snapshot_group_manifest.json")

    probe_summaries = {}

    for probe in PROBES:
        snap = group.get("snapshots", {}).get(probe)
        if not snap:
            raise RuntimeError(f"missing snapshot for {probe}")

        gz_path = Path(snap["local_path"])
        if not gz_path.exists():
            raise FileNotFoundError(gz_path)

        raw_json = raw_dir / f"{probe}_vrps.raw.json"
        decompress_gzip(gz_path, raw_json)

        probe_summaries[probe] = normalize_probe(
            raw_json=raw_json,
            probe=probe,
            normalized_dir=normalized_dir,
            work_dir=work_dir,
        )

    roots = {p: s["vrp_root_v1"] for p, s in probe_summaries.items()}
    all_roots_aligned = len(set(roots.values())) == 1

    summary = {
        "schema": "s3.stage3.m14.vrp_summary.v1",
        "run_id": args.run_id,
        "created_at_utc": utc_now(),
        "source": "p5_auto_from_snapshot_group",
        "snapshot_group_id": group.get("snapshot_group_id"),
        "all_vrp_roots_aligned": all_roots_aligned,
        "probe_summaries": probe_summaries,
    }
    write_json(summary_dir / "m14_vrp_summary.json", summary)

    run_manifest = {
        "schema": "s3.stage3.m14.auto_run_manifest.v1",
        "run_id": args.run_id,
        "created_at_utc": utc_now(),
        "snapshot_group_id": group.get("snapshot_group_id"),
        "snapshot_group_complete": group.get("complete"),
        "generated_time_skew_seconds": group.get("generated_time_skew_seconds"),
        "method": "p5_auto_raw_to_summary_plus_lowmem_sort_comm",
        "sample_limit": args.sample_limit,
        "required_probes": PROBES,
    }
    write_json(inputs_dir / "m14_auto_run_manifest.json", run_manifest)

    run_lowmem_diff(repo_root, run_dir, args.sample_limit)

    diff = read_json(diff_dir / "m14_vrp_pairwise_diff.json")

    preliminary_status = "vrp_outputs_aligned" if all_roots_aligned else "real_vrp_output_diff_observed"
    e4_status = "not_e4" if all_roots_aligned else "not_yet_e4"

    verdict = {
        "schema": "s3.stage3.m14.real_preliminary_verdict.v1",
        "run_id": args.run_id,
        "created_at_utc": utc_now(),
        "snapshot_group_id": group.get("snapshot_group_id"),
        "status": preliminary_status,
        "e4_status": e4_status,
        "confirmed_allowed": False,
        "reason": "P5 auto run only performs VRP output comparison. Same-window object/window/validator/fetch/infrastructure contexts are not yet joined.",
        "key_metrics": {
            "all_vrp_roots_aligned": all_roots_aligned,
            "all_pairwise_entry_level_diff_count": diff.get("all_pairwise_entry_level_diff_count"),
            "min_pairwise_jaccard_similarity": diff.get("min_pairwise_jaccard_similarity"),
            "generated_time_skew_seconds": group.get("generated_time_skew_seconds"),
            "probe_unique_vrp_count": {
                p: s.get("unique_vrp_count") for p, s in probe_summaries.items()
            },
            "probe_parse_error_count": {
                p: s.get("parse_error_count") for p, s in probe_summaries.items()
            },
        },
        "next_required_contexts": [
            "object_layer_context",
            "validator_config_context",
            "window_mapping_context",
            "fetch_completeness_context",
            "infrastructure_context",
        ],
    }
    write_json(verdict_dir / "preliminary_verdict.json", verdict)

    verdict_txt = f"""P5_M14A_AUTO_PRELIMINARY_VERDICT=DONE

run_id = {args.run_id}
snapshot_group_id = {group.get("snapshot_group_id")}

status = {preliminary_status}
e4_status = {e4_status}
confirmed_allowed = False

all_vrp_roots_aligned = {all_roots_aligned}
all_pairwise_entry_level_diff_count = {diff.get("all_pairwise_entry_level_diff_count")}
min_pairwise_jaccard_similarity = {diff.get("min_pairwise_jaccard_similarity")}
generated_time_skew_seconds = {group.get("generated_time_skew_seconds")}

interpretation:
  P5 auto run has completed VRP output comparison from a complete uploaded snapshot group.
  This is still not E4 confirmed because P6 contexts are not joined yet.
"""
    (verdict_dir / "99_m14_p5_preliminary_verdict.txt").write_text(verdict_txt, encoding="utf-8")

    # update group manifest with run_id
    group["m14_run_id"] = args.run_id
    group["m14_run_dir"] = str(run_dir)
    group["updated_at_utc"] = utc_now()
    write_json(group_manifest_path, group)

    acceptance = f"""P5_AUTO_M14A_LOWMEM_DIFF=DONE

run_id = {args.run_id}
run_dir = {run_dir}
snapshot_group_id = {group.get("snapshot_group_id")}

snapshot_group_complete = {group.get("complete")}
received_probes = {group.get("received_probes")}
generated_time_skew_seconds = {group.get("generated_time_skew_seconds")}

raw_inputs_complete = {all((raw_dir / f"{p}_vrps.raw.json").exists() for p in PROBES)}
normalized_outputs_complete = {all((normalized_dir / f"{p}_vrp_index.jsonl").exists() for p in PROBES)}
summary_exists = {(summary_dir / "m14_vrp_summary.json").exists()}
pairwise_diff_exists = {(diff_dir / "m14_vrp_pairwise_diff.json").exists()}
preliminary_verdict_exists = {(verdict_dir / "preliminary_verdict.json").exists()}

status = {preliminary_status}
e4_status = {e4_status}
confirmed_allowed = False

all_vrp_roots_aligned = {all_roots_aligned}
all_pairwise_entry_level_diff_count = {diff.get("all_pairwise_entry_level_diff_count")}
min_pairwise_jaccard_similarity = {diff.get("min_pairwise_jaccard_similarity")}

group_manifest_updated_with_run_id = True

P5_acceptance = True
"""
    (checks_dir / "P5_acceptance_check.txt").write_text(acceptance, encoding="utf-8")

    update_sha256s(run_dir)

    print(json.dumps({
        "status": "done",
        "run_id": args.run_id,
        "run_dir": str(run_dir),
        "snapshot_group_id": group.get("snapshot_group_id"),
        "preliminary_status": preliminary_status,
        "e4_status": e4_status,
        "all_pairwise_entry_level_diff_count": diff.get("all_pairwise_entry_level_diff_count"),
        "min_pairwise_jaccard_similarity": diff.get("min_pairwise_jaccard_similarity"),
        "acceptance_check": str(checks_dir / "P5_acceptance_check.txt"),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
