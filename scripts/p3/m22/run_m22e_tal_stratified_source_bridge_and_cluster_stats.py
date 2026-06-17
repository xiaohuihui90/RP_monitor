#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
from pathlib import Path
from collections import Counter, defaultdict
from urllib.parse import urlparse
from datetime import datetime, timezone


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iter_jsonl(path: Path):
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def load_json_any(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None


def valid_prefix(x):
    if x is None:
        return ""
    try:
        return str(ipaddress.ip_network(str(x).strip(), strict=False))
    except Exception:
        return ""


def norm_tal(x):
    return str(x or "").strip().lower()


def norm_afi_from_prefix(prefix):
    try:
        n = ipaddress.ip_network(prefix, strict=False)
        return "ipv4" if n.version == 4 else "ipv6"
    except Exception:
        return ""


def norm_afi(x, prefix=""):
    s = str(x or "").strip().lower()
    if s in ("ipv4", "ipv6"):
        return s
    return norm_afi_from_prefix(prefix)


def norm_asn(x):
    s = str(x or "").strip()
    if not s:
        return ""
    if s.upper().startswith("AS"):
        s = s[2:]
    if s.isdigit():
        return "AS" + s
    return ""


def asn_num(asn):
    s = norm_asn(asn)
    return s[2:] if s.startswith("AS") else ""


def norm_maxlen(o):
    for k in ["maxLength", "max_length", "maxlength", "max_len"]:
        if k in o and o.get(k) not in (None, ""):
            return str(o.get(k))
    return ""


def make_key(afi, tal, prefix, asn, maxlen):
    afi = norm_afi(afi, prefix)
    tal = norm_tal(tal)
    prefix = valid_prefix(prefix)
    an = asn_num(asn)
    maxlen = str(maxlen or "").strip()
    if afi and tal and prefix and an and maxlen:
        return f"{afi}|{tal}|{prefix}|{an}|{maxlen}"
    return ""


def make_loose_key(afi, prefix, asn, maxlen):
    afi = norm_afi(afi, prefix)
    prefix = valid_prefix(prefix)
    an = asn_num(asn)
    maxlen = str(maxlen or "").strip()
    if afi and prefix and an and maxlen:
        return f"{afi}|{prefix}|{an}|{maxlen}"
    return ""


def uri_host(uri):
    if not uri:
        return ""
    return urlparse(uri).netloc


def uri_base(uri):
    if not uri:
        return ""
    return uri.rsplit("/", 1)[0] + "/" if "/" in uri else uri


def uri_filename(uri):
    if not uri:
        return ""
    return uri.rsplit("/", 1)[-1]


def find_roa_uri(obj):
    """
    宽松递归查找 .roa URI。
    """
    if isinstance(obj, str):
        s = obj.strip()
        if (s.startswith("rsync://") or s.startswith("https://") or s.startswith("http://")) and ".roa" in s:
            return s
        return ""

    if isinstance(obj, dict):
        preferred = [
            "roa_uri", "roaURI", "source_uri", "sourceUri",
            "jsonext_source_uri", "fetch_target_uri", "uri", "source",
            "object_uri", "rpkiObjectUri",
        ]
        for k in preferred:
            if k in obj:
                got = find_roa_uri(obj.get(k))
                if got:
                    return got
        for v in obj.values():
            got = find_roa_uri(v)
            if got:
                return got

    if isinstance(obj, list):
        for v in obj:
            got = find_roa_uri(v)
            if got:
                return got

    return ""


def extract_vrp_like_record(obj, source_file):
    """
    从任意 dict 中提取 VRP-like 字段。
    支持 tal 缺失时用 loose key。
    """
    if not isinstance(obj, dict):
        return None

    prefix = valid_prefix(obj.get("prefix"))
    if not prefix:
        return None

    asn = norm_asn(obj.get("asn") or obj.get("origin") or obj.get("origin_as") or obj.get("originAS"))
    if not asn:
        return None

    maxlen = norm_maxlen(obj)
    if not maxlen:
        return None

    tal = norm_tal(
        obj.get("tal")
        or obj.get("ta")
        or obj.get("trustAnchor")
        or obj.get("trust_anchor")
        or obj.get("tal_name")
    )
    afi = norm_afi(obj.get("afi"), prefix)
    roa_uri = find_roa_uri(obj)

    if not roa_uri:
        return None

    full_key = make_key(afi, tal, prefix, asn, maxlen) if tal else ""
    loose_key = make_loose_key(afi, prefix, asn, maxlen)

    if not full_key and not loose_key:
        return None

    return {
        "full_key": full_key,
        "loose_key": loose_key,
        "afi": afi,
        "tal": tal,
        "prefix": prefix,
        "asn": asn,
        "maxLength": maxlen,
        "roa_uri": roa_uri,
        "source_file": str(source_file),
    }


def walk_json(obj, source_file, out):
    if isinstance(obj, dict):
        rec = extract_vrp_like_record(obj, source_file)
        if rec:
            out.append(rec)
        for v in obj.values():
            walk_json(v, source_file, out)
    elif isinstance(obj, list):
        for v in obj:
            walk_json(v, source_file, out)


def parse_source_file(path: Path):
    """
    返回该文件中可抽取的 VRP->ROA 记录。
    优先按 JSONL 解析；若抽不到，再尝试整文件 JSON。
    """
    records = []

    # JSONL mode
    parsed_lines = 0
    for o in iter_jsonl(path):
        parsed_lines += 1
        walk_json(o, path, records)

    if records:
        return records, "jsonl"

    # whole JSON mode
    if path.suffix.lower() == ".json":
        obj = load_json_any(path)
        if obj is not None:
            walk_json(obj, path, records)
            if records:
                return records, "json"

    return records, "none"


def build_source_index(source_roots):
    full = {}
    loose = {}
    stats = Counter()
    source_file_counter = Counter()

    files = []
    for root_s in source_roots:
        root = Path(root_s)
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            name = p.name.lower()
            if not (name.endswith(".jsonl") or name.endswith(".json")):
                continue
            # 优先扫描可能含 source/JSONEXT/bridge 的文件，避免扫太多无关文件
            path_s = str(p).lower()
            if not any(x in path_s for x in [
                "jsonext", "source_bridge", "enriched_mapping",
                "actual_cache_replay", "fresh_cache", "vrp_outputs"
            ]):
                continue
            files.append(p)

    for p in files:
        recs, mode = parse_source_file(p)
        stats[f"source_file_mode:{mode}"] += 1
        if not recs:
            continue
        source_file_counter[str(p)] += len(recs)
        for r in recs:
            if r["full_key"]:
                old = full.get(r["full_key"])
                if old is None:
                    full[r["full_key"]] = r
            if r["loose_key"]:
                old = loose.get(r["loose_key"])
                if old is None:
                    loose[r["loose_key"]] = r

    return full, loose, stats, source_file_counter, len(files)


def load_a8(a8_jsonl: Path):
    out = {}
    for o in iter_jsonl(a8_jsonl):
        key = o.get("vrp_key")
        if not key:
            continue
        out[key] = o
    return out


def seed_record_to_keys(o):
    key = o.get("vrp_key") or ""
    afi = o.get("afi")
    tal = o.get("tal")
    prefix = o.get("prefix")
    asn = o.get("asn")
    maxlen = o.get("maxLength")
    if not key:
        key = make_key(afi, tal, prefix, asn, maxlen)
    loose = make_loose_key(afi, prefix, asn, maxlen)
    return key, loose


def evidence_level(row):
    if row.get("strong_l1_binding_ready") is True:
        return "same-window-level"
    if row.get("manifest_uri") and row.get("window_id"):
        return "nearest-window-level"
    if row.get("manifest_uri"):
        return "manifest-level"
    if row.get("roa_uri"):
        return "ROA-level"
    return "VRP-only"


def write_jsonl(path, rows):
    with path.open("w", encoding="utf-8") as w:
        for r in rows:
            w.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")


def write_csv(path, rows, fields):
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed-jsonl", required=True)
    ap.add_argument("--a8-jsonl", required=True)
    ap.add_argument("--source-roots", nargs="+", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    full_index, loose_index, index_stats, source_file_counter, scanned_file_count = build_source_index(args.source_roots)
    a8 = load_a8(Path(args.a8_jsonl))

    rows = []
    counters = Counter()
    by_tal_evidence = Counter()
    by_tal_mapping = Counter()
    by_tal_repo = Counter()
    by_tal_manifest = Counter()
    by_tal_roa = Counter()

    for seed in iter_jsonl(Path(args.seed_jsonl)):
        key, loose = seed_record_to_keys(seed)
        tal = norm_tal(seed.get("tal"))

        mapped = None
        mapping_method = "none"
        if key in full_index:
            mapped = full_index[key]
            mapping_method = "exact_full_key"
        elif loose in loose_index:
            mapped = loose_index[loose]
            mapping_method = "loose_no_tal_key"

        a8_rec = a8.get(key)

        row = {
            "schema": "s3.m22e.tal_stratified_source_bridge_record.v1",
            "vrp_key": key,
            "loose_key": loose,
            "afi": seed.get("afi"),
            "tal": tal,
            "prefix": seed.get("prefix"),
            "asn": seed.get("asn"),
            "maxLength": seed.get("maxLength"),
            "global_duration_windows": seed.get("global_duration_windows"),
            "global_duration_seconds_approx": seed.get("global_duration_seconds_approx"),
            "probe_seen_count": seed.get("probe_seen_count"),
            "seen_probe_set": seed.get("seen_probe_set"),
            "trailing_cache_candidate_v1": seed.get("trailing_cache_candidate_v1"),
            "mapping_method": mapping_method,
            "roa_uri": "",
            "repo_host": "",
            "repo_base": "",
            "roa_filename": "",
            "manifest_uri": "",
            "manifestNumber": "",
            "manifest_thisUpdate": "",
            "manifest_nextUpdate": "",
            "manifest_file_hash": "",
            "window_id": "",
            "nearest_window_delta_sec": "",
            "notification_relation_top": "",
            "source_file_for_roa_uri": "",
            "strong_l1_binding_ready": False,
            "semantic_boundary": "tal_stratified_source_bridge_not_global_prevalence",
        }

        if mapped:
            row["roa_uri"] = mapped.get("roa_uri", "")
            row["source_file_for_roa_uri"] = mapped.get("source_file", "")

        # A8 覆盖时，优先使用 A8 的 ROA/manifest/window 证据
        if a8_rec:
            row["roa_uri"] = a8_rec.get("roa_uri") or row["roa_uri"]
            row["manifest_uri"] = a8_rec.get("manifest_uri") or ""
            row["manifestNumber"] = str(a8_rec.get("manifestNumber") or "")
            row["manifest_thisUpdate"] = a8_rec.get("manifest_thisUpdate") or ""
            row["manifest_nextUpdate"] = a8_rec.get("manifest_nextUpdate") or ""
            row["manifest_file_hash"] = a8_rec.get("manifest_file_hash") or ""
            row["window_id"] = a8_rec.get("window_id") or ""
            row["nearest_window_delta_sec"] = a8_rec.get("nearest_window_delta_sec") or ""
            row["strong_l1_binding_ready"] = bool(a8_rec.get("strong_l1_binding_ready"))
            rel_top = a8_rec.get("notification_like_relation_top") or []
            row["notification_relation_top"] = ";".join([f"{a}:{b}" for a, b in rel_top])

        if row["roa_uri"]:
            row["repo_host"] = uri_host(row["roa_uri"])
            row["repo_base"] = uri_base(row["roa_uri"])
            row["roa_filename"] = uri_filename(row["roa_uri"])
        elif row["manifest_uri"]:
            row["repo_host"] = uri_host(row["manifest_uri"])
            row["repo_base"] = uri_base(row["manifest_uri"])

        row["evidence_level"] = evidence_level(row)

        rows.append(row)

        counters["records"] += 1
        counters[f"tal:{tal}"] += 1
        counters[f"evidence:{row['evidence_level']}"] += 1
        counters[f"mapping_method:{mapping_method}"] += 1
        by_tal_evidence[(tal, row["evidence_level"])] += 1
        by_tal_mapping[(tal, mapping_method)] += 1

        if row["repo_base"]:
            by_tal_repo[(tal, row["repo_base"])] += 1
        if row["manifest_uri"]:
            by_tal_manifest[(tal, row["manifest_uri"])] += 1
        if row["roa_uri"]:
            by_tal_roa[(tal, row["roa_uri"])] += 1

    records_jsonl = out_dir / "m22e_tal_stratified_source_bridge_records.jsonl"
    records_csv = out_dir / "m22e_tal_stratified_source_bridge_records.csv"
    summary_json = out_dir / "m22e_tal_stratified_source_bridge_summary.json"
    summary_md = out_dir / "m22e_tal_stratified_source_bridge_summary.md"
    check_txt = out_dir / "M22E_TAL_STRATIFIED_SOURCE_BRIDGE_CHECK.txt"

    write_jsonl(records_jsonl, rows)
    fields = [
        "vrp_key", "afi", "tal", "prefix", "asn", "maxLength",
        "global_duration_windows", "global_duration_seconds_approx",
        "probe_seen_count", "trailing_cache_candidate_v1",
        "mapping_method", "evidence_level",
        "roa_uri", "repo_host", "repo_base", "roa_filename",
        "manifest_uri", "manifestNumber", "manifest_thisUpdate", "manifest_nextUpdate",
        "manifest_file_hash", "window_id", "nearest_window_delta_sec",
        "notification_relation_top", "source_file_for_roa_uri",
        "semantic_boundary",
    ]
    write_csv(records_csv, rows, fields)

    tal_evidence_rows = [
        {"tal": tal, "evidence_level": ev, "count": count}
        for (tal, ev), count in sorted(by_tal_evidence.items())
    ]
    tal_mapping_rows = [
        {"tal": tal, "mapping_method": mm, "count": count}
        for (tal, mm), count in sorted(by_tal_mapping.items())
    ]
    write_csv(out_dir / "dist_tal_by_evidence_level.csv", tal_evidence_rows, ["tal", "evidence_level", "count"])
    write_csv(out_dir / "dist_tal_by_mapping_method.csv", tal_mapping_rows, ["tal", "mapping_method", "count"])

    summary = {
        "schema": "s3.m22e.tal_stratified_source_bridge_summary.v1",
        "generated_at_utc": utc_now(),
        "seed_jsonl": args.seed_jsonl,
        "a8_jsonl": args.a8_jsonl,
        "source_roots": args.source_roots,
        "scanned_source_file_count": scanned_file_count,
        "source_index_full_key_count": len(full_index),
        "source_index_loose_key_count": len(loose_index),
        "index_stats": dict(index_stats),
        "source_file_top20": source_file_counter.most_common(20),
        "record_count": len(rows),
        "counters": dict(counters),
        "tal_by_evidence_level": tal_evidence_rows,
        "tal_by_mapping_method": tal_mapping_rows,
        "repo_base_top20": Counter(r["repo_base"] for r in rows if r["repo_base"]).most_common(20),
        "manifest_uri_top20": Counter(r["manifest_uri"] for r in rows if r["manifest_uri"]).most_common(20),
        "roa_uri_top20": Counter(r["roa_uri"] for r in rows if r["roa_uri"]).most_common(20),
        "outputs": {
            "records_jsonl": str(records_jsonl),
            "records_csv": str(records_csv),
            "summary_json": str(summary_json),
            "summary_md": str(summary_md),
            "tal_by_evidence_level_csv": str(out_dir / "dist_tal_by_evidence_level.csv"),
            "tal_by_mapping_method_csv": str(out_dir / "dist_tal_by_mapping_method.csv"),
        },
        "interpretation": {
            "purpose": "Move TAL-stratified persistent candidates from VRP-only toward ROA-level and join existing A8 manifest/nearest-window evidence when available.",
            "boundary": "Candidate-level measurement; source bridge depends on available JSONEXT/source records, not exhaustive historical provenance.",
        },
        "semantic_boundary": "tal_stratified_source_bridge_candidate_level_not_global_prevalence",
        "next_stage": "M22F_MANIFEST_MAPPING_FOR_MAPPED_TAL_STRATIFIED_CANDIDATES",
    }
    summary_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    md = []
    md.append("# M22E TAL-stratified Source Bridge and Cluster Stats")
    md.append("")
    md.append(f"- record_count: `{len(rows)}`")
    md.append(f"- scanned_source_file_count: `{scanned_file_count}`")
    md.append(f"- source_index_full_key_count: `{len(full_index)}`")
    md.append(f"- source_index_loose_key_count: `{len(loose_index)}`")
    md.append("")
    md.append("## Counters")
    for k, v in sorted(counters.items()):
        md.append(f"- {k}: `{v}`")
    md.append("")
    md.append("## TAL by Evidence Level")
    for r in tal_evidence_rows:
        md.append(f"- {r['tal']} / {r['evidence_level']}: `{r['count']}`")
    md.append("")
    md.append("## TAL by Mapping Method")
    for r in tal_mapping_rows:
        md.append(f"- {r['tal']} / {r['mapping_method']}: `{r['count']}`")
    md.append("")
    md.append("## Top Repository Base")
    for k, v in summary["repo_base_top20"]:
        md.append(f"- `{k}`: `{v}`")
    md.append("")
    md.append("## Top Manifest URI")
    for k, v in summary["manifest_uri_top20"]:
        md.append(f"- `{k}`: `{v}`")
    md.append("")
    md.append("## Interpretation")
    md.append("- ROA-level means a candidate could be mapped to a ROA URI using available JSONEXT/source evidence.")
    md.append("- Manifest/nearest-window evidence is currently inherited from A8 when the same VRP key exists there.")
    md.append("- Candidates still at VRP-only require additional JSONEXT snapshots or historical source sidecars.")
    summary_md.write_text("\n".join(md) + "\n", encoding="utf-8")

    check_txt.write_text(
        "\n".join([
            "M22E_TAL_STRATIFIED_SOURCE_BRIDGE=PASS",
            f"generated_at_utc = {summary['generated_at_utc']}",
            f"record_count = {len(rows)}",
            f"scanned_source_file_count = {scanned_file_count}",
            f"source_index_full_key_count = {len(full_index)}",
            f"source_index_loose_key_count = {len(loose_index)}",
            f"summary_json = {summary_json}",
            f"summary_md = {summary_md}",
            f"records_jsonl = {records_jsonl}",
            f"records_csv = {records_csv}",
            "semantic_boundary = tal_stratified_source_bridge_candidate_level_not_global_prevalence",
            "next_stage = M22F_MANIFEST_MAPPING_FOR_MAPPED_TAL_STRATIFIED_CANDIDATES",
            "",
        ]),
        encoding="utf-8",
    )

    print(check_txt.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
