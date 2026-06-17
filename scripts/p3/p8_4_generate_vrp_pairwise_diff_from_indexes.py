#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROBES = ["probe-cd", "probe-bj", "probe-sg"]
PAIRS = [
    ("probe-cd", "probe-bj"),
    ("probe-cd", "probe-sg"),
    ("probe-bj", "probe-sg"),
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def norm_asn(v: Any) -> str:
    s = str(v)
    if s.upper().startswith("AS"):
        return s.upper()
    return "AS" + s


def extract_key(obj: Any) -> str:
    if isinstance(obj, str):
        return obj

    if isinstance(obj, dict):
        for k in [
            "key",
            "vrp_key",
            "canonical_key",
            "canonical_vrp_key",
            "vrp_key_v1",
            "canonical",
        ]:
            v = obj.get(k)
            if v not in (None, ""):
                return str(v)

        asn = (
            obj.get("asn")
            or obj.get("asID")
            or obj.get("as_id")
            or obj.get("origin")
            or obj.get("origin_asn")
            or obj.get("asn_value")
        )
        prefix = (
            obj.get("prefix")
            or obj.get("ip_prefix")
            or obj.get("address_prefix")
            or obj.get("prefix_value")
        )
        max_length = (
            obj.get("max_length")
            or obj.get("maxLength")
            or obj.get("maxlen")
            or obj.get("max_len")
        )
        tal = (
            obj.get("tal")
            or obj.get("ta")
            or obj.get("trust_anchor")
            or obj.get("source_tal")
            or obj.get("rir")
        )

        if asn is not None and prefix is not None:
            return "|".join([
                norm_asn(asn),
                str(prefix),
                str(max_length if max_length is not None else ""),
                str(tal if tal is not None else ""),
            ])

    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def extract_tal(obj: Any, key: str) -> str | None:
    if isinstance(obj, dict):
        for k in ["tal", "ta", "trust_anchor", "source_tal", "rir"]:
            v = obj.get(k)
            if v not in (None, ""):
                return str(v).lower()

    lowered = key.lower()
    for tal in ["afrinic", "apnic", "arin", "lacnic", "ripe"]:
        if tal in lowered:
            return tal

    return None


def load_index(path: Path) -> tuple[set[str], dict[str, str]]:
    keys: set[str] = set()
    tal_by_key: dict[str, str] = {}

    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            try:
                obj = json.loads(line)
            except Exception as exc:
                raise RuntimeError(f"JSONL parse error in {path} line {line_no}: {exc}") from exc

            key = extract_key(obj)
            keys.add(key)

            tal = extract_tal(obj, key)
            if tal:
                tal_by_key[key] = tal

    return keys, tal_by_key


def write_lines(path: Path, values: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for x in sorted(values):
            f.write(x)
            f.write("\n")


def top_tal(keys: set[str], *tal_maps: dict[str, str]) -> str | None:
    c: Counter[str] = Counter()
    for k in keys:
        for m in tal_maps:
            v = m.get(k)
            if v:
                c[v] += 1
                break
    if not c:
        return None
    return c.most_common(1)[0][0]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--sample-limit", type=int, default=50)
    args = ap.parse_args()

    run_dir = Path(args.run_dir)
    norm_dir = run_dir / "normalized_vrps"
    diff_dir = run_dir / "diffs"
    work_dir = diff_dir / "_lowmem_work"
    checks_dir = run_dir / "checks"

    diff_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)
    checks_dir.mkdir(parents=True, exist_ok=True)

    key_sets: dict[str, set[str]] = {}
    tal_maps: dict[str, dict[str, str]] = {}

    for probe in PROBES:
        p = norm_dir / f"{probe}_vrp_index.jsonl"
        if not p.exists():
            raise FileNotFoundError(p)
        keys, tal_by_key = load_index(p)
        key_sets[probe] = keys
        tal_maps[probe] = tal_by_key

        write_lines(work_dir / f"{probe}.keys.sorted.txt", keys)

    pair_summary: dict[str, Any] = {}
    pair_samples: dict[str, Any] = {}

    total_diff_count = 0
    min_jaccard: float | None = None

    for left, right in PAIRS:
        pair_name = f"{left}_vs_{right}"

        left_keys = key_sets[left]
        right_keys = key_sets[right]

        only_left = left_keys - right_keys
        only_right = right_keys - left_keys
        common = left_keys & right_keys
        union = left_keys | right_keys

        diff_count = len(only_left) + len(only_right)
        total_diff_count += diff_count

        jaccard = (len(common) / len(union)) if union else 1.0
        if min_jaccard is None or jaccard < min_jaccard:
            min_jaccard = jaccard

        only_left_path = work_dir / f"{pair_name}.only_left.txt"
        only_right_path = work_dir / f"{pair_name}.only_right.txt"
        common_path = work_dir / f"{pair_name}.common.txt"
        diff_all_path = work_dir / f"{pair_name}.diff_all.txt"

        write_lines(only_left_path, only_left)
        write_lines(only_right_path, only_right)
        write_lines(common_path, common)
        write_lines(diff_all_path, only_left | only_right)

        pair_summary[pair_name] = {
            "left_probe": left,
            "right_probe": right,
            "left_count": len(left_keys),
            "right_count": len(right_keys),
            "common_count": len(common),
            "union_count": len(union),
            "only_left_count": len(only_left),
            "only_right_count": len(only_right),
            "entry_level_diff_count": diff_count,
            "jaccard_similarity": jaccard,
            "top_diff_tal": top_tal(only_left | only_right, tal_maps[left], tal_maps[right]),
            "only_left_path": str(only_left_path),
            "only_right_path": str(only_right_path),
            "common_path": str(common_path),
            "diff_all_path": str(diff_all_path),
        }

        pair_samples[pair_name] = {
            "only_left_samples": sorted(only_left)[: args.sample_limit],
            "only_right_samples": sorted(only_right)[: args.sample_limit],
            "common_samples": sorted(common)[: min(args.sample_limit, 10)],
        }

    diff_obj = {
        "schema": "s3.stage3.m14.vrp_pairwise_diff.v1",
        "run_id": args.run_id,
        "created_at_utc": utc_now(),
        "probes": PROBES,
        "all_pairwise_entry_level_diff_count": total_diff_count,
        "min_pairwise_jaccard_similarity": min_jaccard,
        "pair_summary": pair_summary,
    }

    samples_obj = {
        "schema": "s3.stage3.m14.vrp_pairwise_diff_samples.v1",
        "run_id": args.run_id,
        "created_at_utc": utc_now(),
        "sample_limit": args.sample_limit,
        "pair_samples": pair_samples,
    }

    (diff_dir / "m14_vrp_pairwise_diff.json").write_text(
        json.dumps(diff_obj, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    (diff_dir / "m14_vrp_pairwise_diff_samples.json").write_text(
        json.dumps(samples_obj, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    acceptance = f"""M14A_PAIRWISE_DIFF_REPAIR=DONE

run_id = {args.run_id}
run_dir = {run_dir}

normalized_inputs_used = True
pairwise_diff_exists = True
pairwise_diff_samples_exists = True

all_pairwise_entry_level_diff_count = {total_diff_count}
min_pairwise_jaccard_similarity = {min_jaccard}

repair_reason:
  original run_m14a_vrp_min_closure.py generated summary and normalized outputs but did not write pairwise diff files.

M14A_pairwise_repair_acceptance = True
"""

    (checks_dir / "M14A_pairwise_diff_repair_check.txt").write_text(acceptance, encoding="utf-8")

    print(acceptance)


if __name__ == "__main__":
    main()
