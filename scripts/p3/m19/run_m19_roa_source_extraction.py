#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import json
import tarfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SOURCE_KEY_HINTS = {
    "source",
    "source_uri",
    "roa_uri",
    "uri",
    "object_uri",
    "roa",
    "roa_url",
    "roa_path",
    "source_url",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def file_nonempty(path: Path) -> bool:
    return path.exists() and path.is_file() and path.stat().st_size > 0


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def iter_jsonl(path: Path):
    if not file_nonempty(path):
        return
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except Exception:
                    continue


def recursive_keys(obj: Any, prefix: str = "", max_depth: int = 5) -> set[str]:
    if max_depth < 0:
        return set()

    keys = set()

    if isinstance(obj, dict):
        for k, v in obj.items():
            ks = str(k)
            full = f"{prefix}.{ks}" if prefix else ks
            keys.add(full)
            keys.update(recursive_keys(v, full, max_depth - 1))

    elif isinstance(obj, list):
        for item in obj[:20]:
            keys.update(recursive_keys(item, prefix, max_depth - 1))

    return keys


def has_source_like_key(obj: Any) -> tuple[bool, list[str]]:
    keys = recursive_keys(obj)
    matched = []

    for k in keys:
        leaf = k.split(".")[-1].lower()
        full = k.lower()

        if leaf in SOURCE_KEY_HINTS:
            matched.append(k)
        elif "source" in full:
            matched.append(k)
        elif "roa_uri" in full:
            matched.append(k)

    return bool(matched), sorted(set(matched))


def extract_source_values(obj: Any, out: list[str], max_values: int = 20) -> None:
    if len(out) >= max_values:
        return

    if isinstance(obj, dict):
        for k, v in obj.items():
            lk = str(k).lower()
            if lk in SOURCE_KEY_HINTS or "source" in lk or "roa_uri" in lk:
                if isinstance(v, str):
                    out.append(v)
                elif isinstance(v, dict):
                    # 常见 jsonext source 可能是对象
                    out.append(json.dumps(v, ensure_ascii=False, sort_keys=True)[:300])
                elif isinstance(v, list):
                    out.append(json.dumps(v[:3], ensure_ascii=False, sort_keys=True)[:300])
            extract_source_values(v, out, max_values)

    elif isinstance(obj, list):
        for x in obj[:20]:
            extract_source_values(x, out, max_values)


def iter_vrp_like_records(obj: Any):
    """
    尽量兼容 Routinator json/jsonext:
    - {"roas": [...]}
    - {"validated_roas": [...]}
    - {"vrps": [...]}
    - [...]
    """
    if isinstance(obj, list):
        for x in obj:
            if isinstance(x, dict):
                yield x
        return

    if isinstance(obj, dict):
        for key in ["roas", "validated_roas", "vrps", "vrp", "payloads"]:
            v = obj.get(key)
            if isinstance(v, list):
                for x in v:
                    if isinstance(x, dict):
                        yield x
                return

        # fallback：递归找第一个 list[dict] 且包含 prefix/asn/maxLength 类字段
        for v in obj.values():
            if isinstance(v, list) and v and isinstance(v[0], dict):
                sample_keys = {str(k).lower() for k in v[0].keys()}
                if {"prefix", "asn"} & sample_keys:
                    for x in v:
                        if isinstance(x, dict):
                            yield x
                    return


def scan_jsonl_records(path: Path, max_records: int) -> dict[str, Any]:
    total = 0
    source_like_count = 0
    key_counter = Counter()
    source_key_counter = Counter()
    sample_source_values = []

    for rec in iter_jsonl(path):
        total += 1
        for k in rec.keys():
            key_counter[str(k)] += 1

        ok, source_keys = has_source_like_key(rec)
        if ok:
            source_like_count += 1
            for k in source_keys:
                source_key_counter[k] += 1
            extract_source_values(rec, sample_source_values)

        if total >= max_records:
            break

    return {
        "path": str(path),
        "record_sample_count": total,
        "source_like_record_count": source_like_count,
        "source_like_ratio": source_like_count / total if total else 0,
        "top_level_keys": key_counter.most_common(50),
        "source_like_keys": source_key_counter.most_common(50),
        "sample_source_values": sample_source_values[:20],
    }


def scan_json_object(path: Path, max_records: int) -> dict[str, Any]:
    try:
        obj = read_json(path)
    except Exception as exc:
        return {
            "path": str(path),
            "parse_status": "json_parse_failed",
            "error": str(exc),
            "record_sample_count": 0,
            "source_like_record_count": 0,
        }

    total = 0
    source_like_count = 0
    key_counter = Counter()
    source_key_counter = Counter()
    sample_source_values = []

    root_keys = sorted(obj.keys()) if isinstance(obj, dict) else []

    for rec in iter_vrp_like_records(obj):
        total += 1

        for k in rec.keys():
            key_counter[str(k)] += 1

        ok, source_keys = has_source_like_key(rec)
        if ok:
            source_like_count += 1
            for k in source_keys:
                source_key_counter[k] += 1
            extract_source_values(rec, sample_source_values)

        if total >= max_records:
            break

    return {
        "path": str(path),
        "parse_status": "ok",
        "root_keys": root_keys,
        "record_sample_count": total,
        "source_like_record_count": source_like_count,
        "source_like_ratio": source_like_count / total if total else 0,
        "top_level_keys": key_counter.most_common(50),
        "source_like_keys": source_key_counter.most_common(50),
        "sample_source_values": sample_source_values[:20],
    }


def scan_json_from_tar(tar_path: Path, max_records: int) -> list[dict[str, Any]]:
    out = []

    try:
        tf = tarfile.open(tar_path, "r:*")
    except Exception as exc:
        return [{
            "path": str(tar_path),
            "parse_status": "tar_open_failed",
            "error": str(exc),
            "record_sample_count": 0,
            "source_like_record_count": 0,
        }]

    with tf:
        members = [
            m for m in tf.getmembers()
            if m.isfile() and m.name.endswith(".json") and ("raw_vrp" in m.name or "vrp" in m.name)
        ]

        if not members:
            out.append({
                "path": str(tar_path),
                "parse_status": "no_json_member_found",
                "record_sample_count": 0,
                "source_like_record_count": 0,
            })
            return out

        for m in members[:3]:
            try:
                f = tf.extractfile(m)
                if f is None:
                    continue
                data = f.read()
                obj = json.loads(data.decode("utf-8", errors="ignore"))
            except Exception as exc:
                out.append({
                    "path": str(tar_path),
                    "member": m.name,
                    "parse_status": "json_member_parse_failed",
                    "error": str(exc),
                    "record_sample_count": 0,
                    "source_like_record_count": 0,
                })
                continue

            total = 0
            source_like_count = 0
            key_counter = Counter()
            source_key_counter = Counter()
            sample_source_values = []

            root_keys = sorted(obj.keys()) if isinstance(obj, dict) else []

            for rec in iter_vrp_like_records(obj):
                total += 1

                for k in rec.keys():
                    key_counter[str(k)] += 1

                ok, source_keys = has_source_like_key(rec)
                if ok:
                    source_like_count += 1
                    for k in source_keys:
                        source_key_counter[k] += 1
                    extract_source_values(rec, sample_source_values)

                if total >= max_records:
                    break

            out.append({
                "path": str(tar_path),
                "member": m.name,
                "parse_status": "ok",
                "root_keys": root_keys,
                "record_sample_count": total,
                "source_like_record_count": source_like_count,
                "source_like_ratio": source_like_count / total if total else 0,
                "top_level_keys": key_counter.most_common(50),
                "source_like_keys": source_key_counter.most_common(50),
                "sample_source_values": sample_source_values[:20],
            })

    return out


def find_raw_sidecar_files(roots: list[Path], max_files: int) -> list[Path]:
    files = []

    for root in roots:
        if not root.exists():
            continue

        patterns = [
            "**/*raw_vrp*.json",
            "**/*raw_vrp*.tar.gz",
            "**/*raw_vrp*.tgz",
        ]

        for pat in patterns:
            files.extend(root.glob(pat))

    # 去重，优先近期修改
    uniq = sorted(set(files), key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
    return uniq[:max_files]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidates", required=True)
    ap.add_argument("--m17-root", default="data/p3_collector/m17_vrp_entry_diff")
    ap.add_argument("--raw-roots", nargs="*", default=[
        "data/p3_collector/m245_three_layer_baseline/raw_vrp_sidecar_incoming",
        "data/p3_collector/m245_three_layer_baseline/history",
        "data/probe/m245_three_layer_baseline/raw_vrp_sidecar",
    ])
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--check-dir", required=True)
    ap.add_argument("--max-records-per-file", type=int, default=5000)
    ap.add_argument("--max-raw-files", type=int, default=12)
    args = ap.parse_args()

    candidates = Path(args.candidates)
    m17_root = Path(args.m17_root)
    raw_roots = [Path(x) for x in args.raw_roots]
    out_dir = Path(args.out_dir)
    check_dir = Path(args.check_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    check_dir.mkdir(parents=True, exist_ok=True)

    candidate_scan = scan_jsonl_records(candidates, args.max_records_per_file)

    m17_diff_files = sorted(m17_root.glob("history/m17_window_*/outputs/vrp_entry_diff_records.jsonl"))
    m17_scans = [
        scan_jsonl_records(p, args.max_records_per_file)
        for p in m17_diff_files
    ]

    canonical_files = sorted(m17_root.glob("history/m17_window_*/outputs/canonical_vrp_manifest.json"))
    canonical_scans = [
        scan_json_object(p, args.max_records_per_file)
        for p in canonical_files[-10:]
    ]

    raw_files = find_raw_sidecar_files(raw_roots, args.max_raw_files)
    raw_scans = []
    for p in raw_files:
        if p.suffix == ".json":
            raw_scans.append(scan_json_object(p, args.max_records_per_file))
        else:
            raw_scans.extend(scan_json_from_tar(p, args.max_records_per_file))

    total_candidate_source = candidate_scan["source_like_record_count"]
    total_m17_source = sum(x.get("source_like_record_count", 0) for x in m17_scans)
    total_raw_source = sum(x.get("source_like_record_count", 0) for x in raw_scans)
    total_raw_sample = sum(x.get("record_sample_count", 0) for x in raw_scans)

    if total_raw_sample == 0:
        diagnosis = "raw_sidecar_not_decodable_or_not_found"
    elif total_raw_source > 0:
        diagnosis = "source_uri_available_in_raw_sidecar"
    elif total_candidate_source > 0 or total_m17_source > 0:
        diagnosis = "source_like_field_available_outside_raw_sidecar"
    else:
        diagnosis = "source_uri_not_available_in_current_json_outputs"

    summary = {
        "schema": "s3.m19.source_uri_extraction_diag.v1",
        "generated_at_utc": utc_now(),
        "status": "PASS",
        "diagnosis": diagnosis,
        "candidate_scan": candidate_scan,
        "m17_diff_file_count": len(m17_diff_files),
        "m17_scans": m17_scans,
        "canonical_file_count": len(canonical_files),
        "canonical_scans": canonical_scans,
        "raw_roots": [str(x) for x in raw_roots],
        "raw_file_count_scanned": len(raw_files),
        "raw_files_scanned": [str(x) for x in raw_files],
        "raw_scans": raw_scans,
        "totals": {
            "candidate_source_like_record_count": total_candidate_source,
            "m17_source_like_record_count": total_m17_source,
            "raw_source_like_record_count": total_raw_source,
            "raw_record_sample_count": total_raw_sample,
        },
        "interpretation": {
            "if_source_missing": "M19 v1 should use object-index fallback and scope classification.",
            "if_source_available": "M19 can use Routinator source URI as weak candidate evidence, not strong causality.",
        },
        "semantic_boundary": {
            "mapping_strength": "weak",
            "strong_causal_claim_allowed": False,
            "accepted_object_set_available": False,
        },
        "next_batch": "M19_BATCH_2_OBJECT_INDEX",
    }

    write_json(out_dir / "m19_source_uri_extraction_diag.json", summary)

    md = []
    md.append("# M19 Source URI Extraction Diagnostic")
    md.append("")
    md.append(f"- generated_at_utc: `{summary['generated_at_utc']}`")
    md.append(f"- status: `{summary['status']}`")
    md.append(f"- diagnosis: `{diagnosis}`")
    md.append("")
    md.append("## Totals")
    md.append("")
    for k, v in summary["totals"].items():
        md.append(f"- {k}: `{v}`")
    md.append("")
    md.append("## Raw files scanned")
    md.append("")
    for p in summary["raw_files_scanned"][:20]:
        md.append(f"- `{p}`")
    md.append("")
    md.append("## Semantic boundary")
    md.append("")
    for k, v in summary["semantic_boundary"].items():
        md.append(f"- {k}: `{v}`")
    md.append("")
    md.append(f"next_batch: `{summary['next_batch']}`")
    (out_dir / "m19_source_uri_extraction_diag.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    lines = [
        "M19_SOURCE_URI_EXTRACTION_DIAG=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"diagnosis = {diagnosis}",
        f"candidate_source_like_record_count = {total_candidate_source}",
        f"m17_source_like_record_count = {total_m17_source}",
        f"raw_source_like_record_count = {total_raw_source}",
        f"raw_record_sample_count = {total_raw_sample}",
        f"raw_file_count_scanned = {len(raw_files)}",
        f"summary_json = {out_dir / 'm19_source_uri_extraction_diag.json'}",
        f"summary_md = {out_dir / 'm19_source_uri_extraction_diag.md'}",
        "mapping_strength = weak",
        "strong_causal_claim_allowed = False",
        "next_batch = M19_BATCH_2_OBJECT_INDEX",
    ]

    (check_dir / "M19_SOURCE_URI_EXTRACTION_DIAG_CHECK.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
