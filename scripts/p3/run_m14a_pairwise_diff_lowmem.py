#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


PROBES = ["probe-cd", "probe-bj", "probe-sg"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_keys(index_path: Path, key_path: Path) -> int:
    count = 0
    with index_path.open("r", encoding="utf-8") as fin, key_path.open("w", encoding="utf-8") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            key = obj["canonical_key"]
            fout.write(key + "\n")
            count += 1
    return count


def sort_unique(src: Path, dst: Path) -> None:
    # LC_ALL=C makes sort/comm deterministic and faster.
    cmd = f"LC_ALL=C sort -u {src} > {dst}"
    subprocess.run(cmd, shell=True, check=True)


def count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    out = subprocess.check_output(["wc", "-l", str(path)], text=True)
    return int(out.strip().split()[0])


def run_shell(cmd: str) -> None:
    subprocess.run(cmd, shell=True, check=True, executable="/bin/bash")


def parse_key(key: str) -> tuple[str, str]:
    parts = key.split("|")
    tal = parts[0] if len(parts) > 0 else "unknown"
    prefix = parts[2] if len(parts) > 2 else ""
    afi = "ipv6" if ":" in prefix else "ipv4"
    return tal, afi


def count_breakdown(path: Path) -> tuple[dict[str, int], dict[str, int]]:
    tal_counter = Counter()
    afi_counter = Counter()
    if not path.exists():
        return {}, {}
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            key = line.strip()
            if not key:
                continue
            tal, afi = parse_key(key)
            tal_counter[tal] += 1
            afi_counter[afi] += 1
    return dict(sorted(tal_counter.items())), dict(sorted(afi_counter.items()))


def sample_lines(path: Path, limit: int) -> list[str]:
    out = []
    if not path.exists():
        return out
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if len(out) >= limit:
                break
            line = line.strip()
            if line:
                out.append(line)
    return out


def update_sha256s(run_dir: Path) -> None:
    out = run_dir / "checks" / "SHA256SUMS.txt"
    rows = []
    for p in sorted(run_dir.rglob("*")):
        if p.is_file() and p != out:
            rows.append((sha256_file(p), str(p.relative_to(run_dir))))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(f"{digest}  {rel}\n" for digest, rel in rows), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--sample-limit", type=int, default=100)
    args = ap.parse_args()

    run_dir = Path(args.run_dir).resolve()
    normalized_dir = run_dir / "normalized_vrps"
    work_dir = run_dir / "diffs" / "_lowmem_work"
    diff_dir = run_dir / "diffs"
    checks_dir = run_dir / "checks"

    work_dir.mkdir(parents=True, exist_ok=True)
    diff_dir.mkdir(parents=True, exist_ok=True)
    checks_dir.mkdir(parents=True, exist_ok=True)

    # 1. Extract canonical keys and sort -u.
    sorted_key_files = {}
    key_counts = {}
    for probe in PROBES:
        index_path = normalized_dir / f"{probe}_vrp_index.jsonl"
        if not index_path.exists():
            raise FileNotFoundError(index_path)

        raw_keys = work_dir / f"{probe}.keys.txt"
        sorted_keys = work_dir / f"{probe}.keys.sorted.txt"

        key_counts[probe] = extract_keys(index_path, raw_keys)
        sort_unique(raw_keys, sorted_keys)
        sorted_key_files[probe] = sorted_keys

    # 2. Pairwise comm.
    pair_summary = {}
    samples = {}

    total_diff = 0
    min_jaccard = None

    pairs = [
        ("probe-cd", "probe-bj"),
        ("probe-cd", "probe-sg"),
        ("probe-bj", "probe-sg"),
    ]

    for left, right in pairs:
        left_file = sorted_key_files[left]
        right_file = sorted_key_files[right]
        pair_name = f"{left}_vs_{right}"

        only_left_file = work_dir / f"{pair_name}.only_left.txt"
        only_right_file = work_dir / f"{pair_name}.only_right.txt"
        common_file = work_dir / f"{pair_name}.common.txt"
        diff_all_file = work_dir / f"{pair_name}.diff_all.txt"

        run_shell(f"LC_ALL=C comm -23 {left_file} {right_file} > {only_left_file}")
        run_shell(f"LC_ALL=C comm -13 {left_file} {right_file} > {only_right_file}")
        run_shell(f"LC_ALL=C comm -12 {left_file} {right_file} > {common_file}")
        run_shell(f"cat {only_left_file} {only_right_file} > {diff_all_file}")

        left_count = count_lines(left_file)
        right_count = count_lines(right_file)
        common_count = count_lines(common_file)
        only_left_count = count_lines(only_left_file)
        only_right_count = count_lines(only_right_file)
        entry_level_diff_count = only_left_count + only_right_count

        union_count = left_count + right_count - common_count
        jaccard = 1.0 if union_count == 0 else common_count / union_count

        tal_breakdown, afi_breakdown = count_breakdown(diff_all_file)
        top_diff_tal = None
        if tal_breakdown:
            top_diff_tal = sorted(tal_breakdown.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]

        total_diff += entry_level_diff_count
        min_jaccard = jaccard if min_jaccard is None else min(min_jaccard, jaccard)

        pair_summary[pair_name] = {
            "left_probe": left,
            "right_probe": right,
            "left_count": left_count,
            "right_count": right_count,
            "common_count": common_count,
            "only_left_count": only_left_count,
            "only_right_count": only_right_count,
            "entry_level_diff_count": entry_level_diff_count,
            "jaccard_similarity": jaccard,
            "top_diff_tal": top_diff_tal,
            "tal_diff_breakdown": tal_breakdown,
            "afi_diff_breakdown": afi_breakdown,
            "lowmem_artifacts": {
                "only_left_file": str(only_left_file.relative_to(run_dir)),
                "only_right_file": str(only_right_file.relative_to(run_dir)),
                "common_file": str(common_file.relative_to(run_dir)),
            },
        }

        samples[pair_name] = {
            "only_left": sample_lines(only_left_file, args.sample_limit),
            "only_right": sample_lines(only_right_file, args.sample_limit),
        }

    diff_obj = {
        "schema": "s3.stage3.m14.vrp_pairwise_diff.v1",
        "run_id": run_dir.name,
        "created_at_utc": utc_now(),
        "method": "lowmem_sort_comm",
        "pair_summary": pair_summary,
        "all_pairwise_entry_level_diff_count": total_diff,
        "min_pairwise_jaccard_similarity": min_jaccard,
    }

    sample_obj = {
        "schema": "s3.stage3.m14.vrp_diff_samples.v1",
        "run_id": run_dir.name,
        "created_at_utc": utc_now(),
        "method": "lowmem_sort_comm",
        "sample_limit_per_pair": args.sample_limit,
        "samples": samples,
    }

    write_json(diff_dir / "m14_vrp_pairwise_diff.json", diff_obj)
    write_json(diff_dir / "m14_vrp_pairwise_diff_samples.json", sample_obj)

    summary_path = run_dir / "summaries" / "m14_vrp_summary.json"
    summary = read_json(summary_path) if summary_path.exists() else {}

    raw_complete = all(any((run_dir / "raw_vrps").glob(f"{p}_vrps.raw.*")) for p in PROBES)
    norm_complete = all((normalized_dir / f"{p}_vrp_index.jsonl").exists() for p in PROBES)
    summary_exists = summary_path.exists()
    diff_exists = (diff_dir / "m14_vrp_pairwise_diff.json").exists()

    lines = [
        "M14A_VRP_MIN_CLOSURE=DONE",
        "",
        f"run_id = {run_dir.name}",
        f"run_dir = {run_dir}",
        "method = lowmem_sort_comm_resume",
        "",
        f"raw_inputs_complete = {raw_complete}",
        f"normalized_outputs_complete = {norm_complete}",
        f"summary_exists = {summary_exists}",
        f"pairwise_diff_exists = {diff_exists}",
        f"all_vrp_roots_aligned = {summary.get('all_vrp_roots_aligned')}",
        f"all_pairwise_entry_level_diff_count = {diff_obj.get('all_pairwise_entry_level_diff_count')}",
        f"min_pairwise_jaccard_similarity = {diff_obj.get('min_pairwise_jaccard_similarity')}",
        "",
        "probe_summaries:",
    ]

    for probe, ps in summary.get("probe_summaries", {}).items():
        lines.append(
            f"  {probe}: unique_vrp_count={ps.get('unique_vrp_count')} "
            f"parse_error_count={ps.get('parse_error_count')} "
            f"vrp_root_v1={ps.get('vrp_root_v1')}"
        )

    lines.append("")
    lines.append("pair_summary:")
    for pair_name, ps in pair_summary.items():
        lines.append(
            f"  {pair_name}: left={ps['left_count']} right={ps['right_count']} "
            f"common={ps['common_count']} only_left={ps['only_left_count']} "
            f"only_right={ps['only_right_count']} jaccard={ps['jaccard_similarity']}"
        )

    (checks_dir / "M14A_acceptance_check.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    update_sha256s(run_dir)

    print(json.dumps({
        "status": "done",
        "run_id": run_dir.name,
        "method": "lowmem_sort_comm_resume",
        "all_pairwise_entry_level_diff_count": diff_obj.get("all_pairwise_entry_level_diff_count"),
        "min_pairwise_jaccard_similarity": diff_obj.get("min_pairwise_jaccard_similarity"),
        "acceptance_check": str(checks_dir / "M14A_acceptance_check.txt"),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
