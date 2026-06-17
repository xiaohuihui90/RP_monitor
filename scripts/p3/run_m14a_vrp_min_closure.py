#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import shutil
from collections import Counter, defaultdict
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path
from typing import Any


PROBES = ["probe-cd", "probe-bj", "probe-sg"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_dirs(run_dir: Path) -> None:
    for name in [
        "inputs",
        "raw_vrps",
        "normalized_vrps",
        "summaries",
        "diffs",
        "checks",
        "logs",
    ]:
        (run_dir / name).mkdir(parents=True, exist_ok=True)


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_asn(value: Any) -> int:
    if value is None:
        raise ValueError("missing_asn")
    s = str(value).strip().upper()
    if s.startswith("AS"):
        s = s[2:]
    s = s.strip()
    if not s or not s.isdigit():
        raise ValueError(f"invalid_asn:{value}")
    return int(s)


def normalize_prefix(value: Any) -> tuple[str, str, int, int]:
    if value is None:
        raise ValueError("missing_prefix")
    net = ipaddress.ip_network(str(value).strip(), strict=False)
    afi = "ipv4" if net.version == 4 else "ipv6"
    prefix = str(net)
    prefix_length = int(net.prefixlen)
    prefix_int = int(net.network_address)
    return prefix, afi, prefix_length, prefix_int


def pick_first(raw: dict[str, Any], names: list[str]) -> Any:
    for name in names:
        if name in raw and raw[name] not in (None, ""):
            return raw[name]
    return None


def extract_tal(raw: dict[str, Any]) -> str:
    direct = pick_first(raw, ["tal", "ta", "trust_anchor", "trustAnchor"])
    if direct:
        return str(direct).strip().lower()

    source = raw.get("source")
    if isinstance(source, dict):
        v = pick_first(source, ["tal", "ta", "trust_anchor", "trustAnchor"])
        if v:
            return str(v).strip().lower()

    return "unknown"


def extract_roas_from_json(path: Path) -> list[dict[str, Any]]:
    obj = read_json(path)
    if isinstance(obj, list):
        return [x for x in obj if isinstance(x, dict)]
    if isinstance(obj, dict):
        roas = obj.get("roas")
        if isinstance(roas, list):
            return [x for x in roas if isinstance(x, dict)]
        # Some exports may use routes/vrps/validated_roas.
        for key in ["vrps", "routes", "validated_roas", "validatedROAs"]:
            items = obj.get(key)
            if isinstance(items, list):
                return [x for x in items if isinstance(x, dict)]
    raise ValueError(f"unsupported_json_shape:{path}")


def load_raw_records(path: Path) -> list[dict[str, Any]]:
    suffix = path.suffix.lower()

    if suffix == ".json":
        return extract_roas_from_json(path)

    if suffix == ".jsonl":
        out: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                if isinstance(obj, dict) and "roas" in obj:
                    roas = obj.get("roas")
                    if isinstance(roas, list):
                        out.extend([x for x in roas if isinstance(x, dict)])
                elif isinstance(obj, dict):
                    out.append(obj)
        return out

    if suffix == ".csv":
        with path.open("r", encoding="utf-8", newline="") as f:
            return list(csv.DictReader(f))

    raise ValueError(f"unsupported_raw_format:{path}")


def normalize_record(
    raw: dict[str, Any],
    source_probe: str,
    source_validator: str,
    source_file: str,
    raw_line_no: int,
) -> tuple[dict[str, Any] | None, str | None]:
    try:
        asn_value = pick_first(raw, ["asn", "as", "origin", "origin_as", "originAS", "asn_text"])
        prefix_value = pick_first(raw, ["prefix", "prefix_addr", "net", "route"])
        maxlen_value = pick_first(raw, ["maxLength", "max_length", "max_len", "maxlength"])

        asn = normalize_asn(asn_value)
        prefix, afi, prefix_length, prefix_int = normalize_prefix(prefix_value)

        warning = None
        if maxlen_value in (None, ""):
            max_length = prefix_length
            warning = "missing_max_length_defaulted_to_prefix_length"
        else:
            max_length = int(str(maxlen_value).strip())

        tal = extract_tal(raw)
        canonical_key = f"{tal}|AS{asn}|{prefix}|{max_length}"

        entry = {
            "schema": "s3.stage3.m14.canonical_vrp.v1",
            "tal": tal,
            "asn": asn,
            "asn_text": f"AS{asn}",
            "prefix": prefix,
            "prefix_length": prefix_length,
            "prefix_int": prefix_int,
            "max_length": max_length,
            "afi": afi,
            "source_validator": source_validator,
            "source_probe": source_probe,
            "source_file": source_file,
            "raw_line_no": raw_line_no,
            "canonical_key": canonical_key,
        }
        return entry, warning
    except Exception as exc:
        return None, str(exc)


def sort_entry_key(entry: dict[str, Any]) -> tuple[Any, ...]:
    return (
        entry["tal"],
        entry["afi"],
        int(entry["prefix_int"]),
        int(entry["prefix_length"]),
        int(entry["max_length"]),
        int(entry["asn"]),
    )


def compute_root(keys: list[str]) -> str:
    h = hashlib.sha256()
    for key in sorted(set(keys)):
        h.update(key.encode("utf-8"))
        h.update(b"\n")
    return "sha256:" + h.hexdigest()


def write_normalized_for_probe(
    raw_path: Path,
    out_path: Path,
    probe: str,
    source_validator: str,
) -> dict[str, Any]:
    raw_records = load_raw_records(raw_path)

    normalized: list[dict[str, Any]] = []
    parse_errors: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []

    for idx, raw in enumerate(raw_records, start=1):
        entry, warning = normalize_record(
            raw=raw,
            source_probe=probe,
            source_validator=source_validator,
            source_file=str(raw_path),
            raw_line_no=idx,
        )
        if entry is None:
            parse_errors.append({"raw_line_no": idx, "error": warning, "raw": raw})
            continue
        if warning:
            warnings.append({"raw_line_no": idx, "warning": warning, "canonical_key": entry["canonical_key"]})
        normalized.append(entry)

    by_key: dict[str, dict[str, Any]] = {}
    duplicate_same_key_count = 0
    duplicate_metadata_diff_count = 0

    for entry in normalized:
        key = entry["canonical_key"]
        if key in by_key:
            duplicate_same_key_count += 1
            old = by_key[key]
            comparable = {k: entry.get(k) for k in ["tal", "asn", "prefix", "max_length", "afi"]}
            old_comp = {k: old.get(k) for k in ["tal", "asn", "prefix", "max_length", "afi"]}
            if comparable != old_comp:
                duplicate_metadata_diff_count += 1
            continue
        by_key[key] = entry

    unique_entries = sorted(by_key.values(), key=sort_entry_key)

    with out_path.open("w", encoding="utf-8") as f:
        for entry in unique_entries:
            f.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")

    keys = [entry["canonical_key"] for entry in unique_entries]
    tal_breakdown = Counter(entry["tal"] for entry in unique_entries)
    afi_breakdown = Counter(entry["afi"] for entry in unique_entries)

    return {
        "probe": probe,
        "raw_file": str(raw_path),
        "normalized_file": str(out_path),
        "raw_vrp_count": len(raw_records),
        "unique_vrp_count": len(unique_entries),
        "duplicate_same_key_count": duplicate_same_key_count,
        "duplicate_metadata_diff_count": duplicate_metadata_diff_count,
        "parse_error_count": len(parse_errors),
        "warning_count": len(warnings),
        "vrp_root_v1": compute_root(keys),
        "tal_breakdown": dict(sorted(tal_breakdown.items())),
        "afi_breakdown": dict(sorted(afi_breakdown.items())),
        "parse_error_samples": parse_errors[:20],
        "warning_samples": warnings[:20],
    }


def load_index_keys(path: Path) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            out[obj["canonical_key"]] = obj
    return out


def parse_canonical_key(key: str) -> dict[str, str]:
    parts = key.split("|")
    tal = parts[0] if len(parts) > 0 else "unknown"
    prefix = parts[2] if len(parts) > 2 else ""
    try:
        afi = "ipv4" if ipaddress.ip_network(prefix, strict=False).version == 4 else "ipv6"
    except Exception:
        afi = "unknown"
    return {"tal": tal, "afi": afi}


def pairwise_diff(run_dir: Path, probes: list[str], sample_limit: int) -> tuple[dict[str, Any], dict[str, Any]]:
    indexes = {
        probe: load_index_keys(run_dir / "normalized_vrps" / f"{probe}_vrp_index.jsonl")
        for probe in probes
    }

    pair_summary: dict[str, Any] = {}
    samples: dict[str, Any] = {}

    total_diff = 0
    min_jaccard = None

    for left, right in combinations(probes, 2):
        left_keys = set(indexes[left])
        right_keys = set(indexes[right])

        common = left_keys & right_keys
        only_left = sorted(left_keys - right_keys)
        only_right = sorted(right_keys - left_keys)
        union_count = len(left_keys | right_keys)
        jaccard = 1.0 if union_count == 0 else len(common) / union_count

        diff_keys = only_left + only_right
        tal_counter = Counter()
        afi_counter = Counter()
        for key in diff_keys:
            parsed = parse_canonical_key(key)
            tal_counter[parsed["tal"]] += 1
            afi_counter[parsed["afi"]] += 1

        pair_name = f"{left}_vs_{right}"
        entry_level_diff_count = len(only_left) + len(only_right)
        total_diff += entry_level_diff_count
        min_jaccard = jaccard if min_jaccard is None else min(min_jaccard, jaccard)

        pair_summary[pair_name] = {
            "left_probe": left,
            "right_probe": right,
            "left_count": len(left_keys),
            "right_count": len(right_keys),
            "common_count": len(common),
            "only_left_count": len(only_left),
            "only_right_count": len(only_right),
            "entry_level_diff_count": entry_level_diff_count,
            "jaccard_similarity": jaccard,
            "top_diff_tal": tal_counter.most_common(1)[0][0] if tal_counter else None,
            "tal_diff_breakdown": dict(sorted(tal_counter.items())),
            "afi_diff_breakdown": dict(sorted(afi_counter.items())),
        }

        samples[pair_name] = {
            "only_left": only_left[:sample_limit],
            "only_right": only_right[:sample_limit],
        }

    diff_obj = {
        "schema": "s3.stage3.m14.vrp_pairwise_diff.v1",
        "run_id": run_dir.name,
        "created_at_utc": utc_now(),
        "pair_summary": pair_summary,
        "all_pairwise_entry_level_diff_count": total_diff,
        "min_pairwise_jaccard_similarity": min_jaccard,
    }

    sample_obj = {
        "schema": "s3.stage3.m14.vrp_diff_samples.v1",
        "run_id": run_dir.name,
        "created_at_utc": utc_now(),
        "sample_limit_per_pair": sample_limit,
        "samples": samples,
    }

    return diff_obj, sample_obj


def make_fixture_raw(run_dir: Path) -> dict[str, Path]:
    fixture = {
        "probe-cd": {
            "metadata": {"generatedTime": "2026-05-07T12:00:00Z"},
            "roas": [
                {"asn": "AS64496", "prefix": "203.0.113.0/24", "maxLength": 24, "ta": "ripe"},
                {"asn": "AS64497", "prefix": "198.51.100.0/24", "maxLength": 24, "ta": "arin"},
                {"asn": "AS64498", "prefix": "2001:db8::/32", "maxLength": 48, "ta": "apnic"},
            ],
        },
        "probe-bj": {
            "metadata": {"generatedTime": "2026-05-07T12:00:00Z"},
            "roas": [
                {"asn": "AS64496", "prefix": "203.0.113.0/24", "maxLength": 24, "ta": "ripe"},
                {"asn": "AS64497", "prefix": "198.51.100.0/24", "maxLength": 24, "ta": "arin"},
                {"asn": "AS64500", "prefix": "2001:db8:1::/48", "maxLength": 48, "ta": "apnic"},
            ],
        },
        "probe-sg": {
            "metadata": {"generatedTime": "2026-05-07T12:00:00Z"},
            "roas": [
                {"asn": "AS64496", "prefix": "203.0.113.0/24", "maxLength": 24, "ta": "ripe"},
                {"asn": "AS64497", "prefix": "198.51.100.0/24", "maxLength": 24, "ta": "arin"},
                {"asn": "AS64498", "prefix": "2001:db8::/32", "maxLength": 48, "ta": "apnic"},
            ],
        },
    }

    out: dict[str, Path] = {}
    for probe, obj in fixture.items():
        path = run_dir / "raw_vrps" / f"{probe}_vrps.raw.json"
        write_json(path, obj)
        out[probe] = path
    return out


def copy_raw_inputs(run_dir: Path, args: argparse.Namespace) -> dict[str, Path]:
    mapping = {
        "probe-cd": args.probe_cd_file,
        "probe-bj": args.probe_bj_file,
        "probe-sg": args.probe_sg_file,
    }

    out: dict[str, Path] = {}
    for probe, file_value in mapping.items():
        if not file_value:
            continue
        src = Path(file_value).expanduser().resolve()
        if not src.exists():
            raise FileNotFoundError(f"{probe} raw VRP file not found: {src}")
        dst = run_dir / "raw_vrps" / f"{probe}_vrps.raw{src.suffix.lower()}"
        shutil.copy2(src, dst)
        out[probe] = dst
    return out


def find_existing_raw(run_dir: Path) -> dict[str, Path]:
    out: dict[str, Path] = {}
    for probe in PROBES:
        candidates = []
        for suffix in [".json", ".jsonl", ".csv"]:
            candidates.extend((run_dir / "raw_vrps").glob(f"{probe}_vrps.raw{suffix}"))
        if candidates:
            out[probe] = sorted(candidates)[0]
    return out


def build_summary(run_dir: Path, probe_summaries: dict[str, Any]) -> dict[str, Any]:
    roots = defaultdict(list)
    for probe, summary in probe_summaries.items():
        roots[summary["vrp_root_v1"]].append(probe)

    return {
        "schema": "s3.stage3.m14.vrp_summary.v1",
        "run_id": run_dir.name,
        "created_at_utc": utc_now(),
        "probe_summaries": probe_summaries,
        "all_vrp_roots_aligned": len(roots) == 1,
        "root_groups": [
            {"vrp_root_v1": root, "probes": sorted(probes)}
            for root, probes in sorted(roots.items())
        ],
        "input_validation": {
            "all_raw_inputs_exist": all((run_dir / "raw_vrps" / f"{p}_vrps.raw.json").exists()
                                        or (run_dir / "raw_vrps" / f"{p}_vrps.raw.jsonl").exists()
                                        or (run_dir / "raw_vrps" / f"{p}_vrps.raw.csv").exists()
                                        for p in PROBES),
            "all_normalized_outputs_exist": all((run_dir / "normalized_vrps" / f"{p}_vrp_index.jsonl").exists()
                                                for p in PROBES),
            "all_parse_errors_zero": all(summary["parse_error_count"] == 0 for summary in probe_summaries.values()),
            "all_unique_vrp_count_positive": all(summary["unique_vrp_count"] > 0 for summary in probe_summaries.values()),
        },
    }


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_acceptance(run_dir: Path, summary: dict[str, Any], diff: dict[str, Any]) -> None:
    required = [
        run_dir / "summaries" / "m14_vrp_summary.json",
        run_dir / "diffs" / "m14_vrp_pairwise_diff.json",
        run_dir / "diffs" / "m14_vrp_pairwise_diff_samples.json",
    ]
    raw_complete = all(any((run_dir / "raw_vrps").glob(f"{p}_vrps.raw.*")) for p in PROBES)
    norm_complete = all((run_dir / "normalized_vrps" / f"{p}_vrp_index.jsonl").exists() for p in PROBES)
    summary_exists = (run_dir / "summaries" / "m14_vrp_summary.json").exists()
    diff_exists = (run_dir / "diffs" / "m14_vrp_pairwise_diff.json").exists()

    lines = [
        "M14A_VRP_MIN_CLOSURE=DONE",
        "",
        f"run_id = {run_dir.name}",
        f"run_dir = {run_dir}",
        "",
        f"raw_inputs_complete = {raw_complete}",
        f"normalized_outputs_complete = {norm_complete}",
        f"summary_exists = {summary_exists}",
        f"pairwise_diff_exists = {diff_exists}",
        f"all_vrp_roots_aligned = {summary.get('all_vrp_roots_aligned')}",
        f"all_pairwise_entry_level_diff_count = {diff.get('all_pairwise_entry_level_diff_count')}",
        f"min_pairwise_jaccard_similarity = {diff.get('min_pairwise_jaccard_similarity')}",
        "",
        "probe_summaries:",
    ]
    for probe, ps in summary["probe_summaries"].items():
        lines.append(
            f"  {probe}: unique_vrp_count={ps['unique_vrp_count']} "
            f"parse_error_count={ps['parse_error_count']} "
            f"vrp_root_v1={ps['vrp_root_v1']}"
        )

    lines.append("")
    lines.append("outputs:")
    for path in required:
        lines.append(f"  {path}")

    (run_dir / "checks" / "M14A_acceptance_check.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    checks = {}
    for p in sorted(run_dir.rglob("*")):
        if p.is_file() and "checks/SHA256SUMS.txt" not in str(p):
            checks[str(p.relative_to(run_dir))] = sha256_file(p)
    with (run_dir / "checks" / "SHA256SUMS.txt").open("w", encoding="utf-8") as f:
        for rel, digest in checks.items():
            f.write(f"{digest}  {rel}\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="M14-A VRP raw -> canonical -> root -> pairwise diff")
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--out-root", default="data/p3_collector/m14_vrp_runs")
    parser.add_argument("--run-dir", default=None)
    parser.add_argument("--fixture", action="store_true", help="create a small synthetic VRP fixture")
    parser.add_argument("--probe-cd-file", default=None)
    parser.add_argument("--probe-bj-file", default=None)
    parser.add_argument("--probe-sg-file", default=None)
    parser.add_argument("--source-validator", default="routinator")
    parser.add_argument("--sample-limit", type=int, default=100)
    args = parser.parse_args()

    if args.run_dir:
        run_dir = Path(args.run_dir).resolve()
    else:
        run_id = args.run_id or f"m14_vrp_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        run_dir = (Path(args.out_root) / run_id).resolve()

    ensure_dirs(run_dir)

    raw_inputs = copy_raw_inputs(run_dir, args)
    if args.fixture:
        raw_inputs = make_fixture_raw(run_dir)
    else:
        raw_inputs.update(find_existing_raw(run_dir))

    if set(raw_inputs) != set(PROBES):
        missing = sorted(set(PROBES) - set(raw_inputs))
        raise SystemExit(
            "missing raw VRP inputs for probes: "
            + ",".join(missing)
            + ". Provide --probe-*-file or use --fixture for smoke test."
        )

    run_manifest = {
        "schema": "s3.stage3.m14a.run_manifest.v1",
        "run_id": run_dir.name,
        "created_at_utc": utc_now(),
        "scope": "M14-A minimal VRP closure only",
        "source_validator": args.source_validator,
        "probes": PROBES,
        "raw_inputs": {probe: str(path) for probe, path in raw_inputs.items()},
    }
    write_json(run_dir / "inputs" / "m14a_run_manifest.json", run_manifest)

    probe_summaries: dict[str, Any] = {}
    for probe in PROBES:
        raw_path = raw_inputs[probe]
        out_path = run_dir / "normalized_vrps" / f"{probe}_vrp_index.jsonl"
        probe_summaries[probe] = write_normalized_for_probe(
            raw_path=raw_path,
            out_path=out_path,
            probe=probe,
            source_validator=args.source_validator,
        )

    summary = build_summary(run_dir, probe_summaries)
    write_json(run_dir / "summaries" / "m14_vrp_summary.json", summary)

    diff, sample = pairwise_diff(run_dir, PROBES, args.sample_limit)
    write_json(run_dir / "diffs" / "m14_vrp_pairwise_diff.json", diff)
    write_json(run_dir / "diffs" / "m14_vrp_pairwise_diff_samples.json", sample)

    write_acceptance(run_dir, summary, diff)

    print(json.dumps({
        "status": "done",
        "run_id": run_dir.name,
        "run_dir": str(run_dir),
        "all_vrp_roots_aligned": summary["all_vrp_roots_aligned"],
        "all_pairwise_entry_level_diff_count": diff["all_pairwise_entry_level_diff_count"],
        "acceptance_check": str(run_dir / "checks" / "M14A_acceptance_check.txt"),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
