#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
from pathlib import Path
from collections import Counter
from urllib.parse import urlparse
from datetime import datetime, timezone


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iter_jsonl(path: Path):
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def norm_prefix(x):
    try:
        return str(ipaddress.ip_network(str(x).strip(), strict=False))
    except Exception:
        return ""


def norm_afi(prefix, afi=""):
    a = str(afi or "").lower()
    if a in ("ipv4", "ipv6"):
        return a
    try:
        n = ipaddress.ip_network(prefix, strict=False)
        return "ipv4" if n.version == 4 else "ipv6"
    except Exception:
        return ""


def norm_asn(x):
    s = str(x or "").strip()
    if s.upper().startswith("AS"):
        s = s[2:]
    if s.isdigit():
        return "AS" + s
    return ""


def asn_num(x):
    s = norm_asn(x)
    return s[2:] if s.startswith("AS") else ""


def norm_maxlen(o):
    for k in ["maxLength", "max_length", "maxlength", "max_len"]:
        if isinstance(o, dict) and o.get(k) not in (None, ""):
            return str(o.get(k))
    return ""


def make_key(afi, tal, prefix, asn, maxlen):
    prefix = norm_prefix(prefix)
    afi = norm_afi(prefix, afi)
    tal = str(tal or "").lower()
    an = asn_num(asn)
    ml = str(maxlen or "").strip()
    if afi and tal and prefix and an and ml:
        return f"{afi}|{tal}|{prefix}|{an}|{ml}"
    return ""


def make_loose_key(afi, prefix, asn, maxlen):
    prefix = norm_prefix(prefix)
    afi = norm_afi(prefix, afi)
    an = asn_num(asn)
    ml = str(maxlen or "").strip()
    if afi and prefix and an and ml:
        return f"{afi}|{prefix}|{an}|{ml}"
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
    if isinstance(obj, str):
        s = obj.strip()
        if (s.startswith("rsync://") or s.startswith("https://") or s.startswith("http://")) and ".roa" in s:
            return s
        return ""

    if isinstance(obj, dict):
        preferred = [
            "roa_uri", "roaURI", "source_uri", "sourceUri", "source",
            "uri", "jsonext_source_uri", "object_uri", "rpkiObjectUri",
            "location", "url"
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


def extract_vrp_records(obj, out):
    if isinstance(obj, dict):
        prefix = norm_prefix(obj.get("prefix"))
        asn = norm_asn(obj.get("asn") or obj.get("origin") or obj.get("origin_as") or obj.get("originAS"))
        maxlen = norm_maxlen(obj)
        tal = str(
            obj.get("tal")
            or obj.get("ta")
            or obj.get("trustAnchor")
            or obj.get("trust_anchor")
            or obj.get("tal_name")
            or ""
        ).lower()
        afi = norm_afi(prefix, obj.get("afi"))

        roa_uri = find_roa_uri(obj)

        if prefix and asn and maxlen and roa_uri:
            full_key = make_key(afi, tal, prefix, asn, maxlen) if tal else ""
            loose_key = make_loose_key(afi, prefix, asn, maxlen)
            out.append({
                "full_key": full_key,
                "loose_key": loose_key,
                "afi": afi,
                "tal": tal,
                "prefix": prefix,
                "asn": asn,
                "maxLength": maxlen,
                "roa_uri": roa_uri,
            })

        for v in obj.values():
            extract_vrp_records(v, out)

    elif isinstance(obj, list):
        for v in obj:
            extract_vrp_records(v, out)


def load_json_or_jsonl(path: Path):
    records = []

    # whole JSON
    try:
        obj = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        extract_vrp_records(obj, records)
        if records:
            return records, "json"
    except Exception:
        pass

    # JSONL fallback
    for obj in iter_jsonl(path):
        extract_vrp_records(obj, records)

    return records, "jsonl"


def write_csv(path, rows, fields):
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed-jsonl", required=True)
    ap.add_argument("--jsonext", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    seed = Path(args.seed_jsonl)
    jsonext = Path(args.jsonext)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    extracted, json_mode = load_json_or_jsonl(jsonext)

    full_index = {}
    loose_index = {}
    for r in extracted:
        if r["full_key"] and r["full_key"] not in full_index:
            full_index[r["full_key"]] = r
        if r["loose_key"] and r["loose_key"] not in loose_index:
            loose_index[r["loose_key"]] = r

    rows = []
    c = Counter()
    tal_evidence = Counter()
    repo = Counter()
    roa = Counter()

    for s in iter_jsonl(seed):
        key = s.get("vrp_key")
        loose = make_loose_key(s.get("afi"), s.get("prefix"), s.get("asn"), s.get("maxLength"))
        tal = str(s.get("tal") or "").lower()

        hit = None
        method = "none"

        if key in full_index:
            hit = full_index[key]
            method = "exact_full_key"
        elif loose in loose_index:
            hit = loose_index[loose]
            method = "loose_key_no_tal"

        roa_uri = hit["roa_uri"] if hit else ""
        evidence = "ROA-level" if roa_uri else "VRP-only"

        row = {
            "vrp_key": key,
            "afi": s.get("afi"),
            "tal": tal,
            "prefix": s.get("prefix"),
            "asn": s.get("asn"),
            "maxLength": s.get("maxLength"),
            "global_duration_windows": s.get("global_duration_windows"),
            "global_duration_seconds_approx": s.get("global_duration_seconds_approx"),
            "probe_seen_count": s.get("probe_seen_count"),
            "trailing_cache_candidate_v1": s.get("trailing_cache_candidate_v1"),
            "mapping_method": method,
            "evidence_level": evidence,
            "roa_uri": roa_uri,
            "repo_host": uri_host(roa_uri),
            "repo_base": uri_base(roa_uri),
            "roa_filename": uri_filename(roa_uri),
            "semantic_boundary": "jsonext_current_snapshot_source_bridge_not_historical_causal_attribution",
        }

        rows.append(row)
        c["records"] += 1
        c[f"evidence:{evidence}"] += 1
        c[f"mapping_method:{method}"] += 1
        c[f"tal:{tal}"] += 1
        tal_evidence[(tal, evidence)] += 1
        if roa_uri:
            repo[row["repo_base"]] += 1
            roa[roa_uri] += 1

    records_csv = out / "m22f_jsonext_source_bridge_records.csv"
    records_jsonl = out / "m22f_jsonext_source_bridge_records.jsonl"
    summary_json = out / "m22f_jsonext_source_bridge_summary.json"
    summary_md = out / "m22f_jsonext_source_bridge_summary.md"
    check_txt = out / "M22F_JSONEXT_SOURCE_BRIDGE_CHECK.txt"

    fields = [
        "vrp_key", "afi", "tal", "prefix", "asn", "maxLength",
        "global_duration_windows", "global_duration_seconds_approx",
        "probe_seen_count", "trailing_cache_candidate_v1",
        "mapping_method", "evidence_level",
        "roa_uri", "repo_host", "repo_base", "roa_filename",
        "semantic_boundary",
    ]
    write_csv(records_csv, rows, fields)

    with records_jsonl.open("w", encoding="utf-8") as w:
        for r in rows:
            w.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")

    tal_evidence_rows = [
        {"tal": tal, "evidence_level": ev, "count": n}
        for (tal, ev), n in sorted(tal_evidence.items())
    ]
    write_csv(out / "dist_tal_by_evidence_level.csv", tal_evidence_rows, ["tal", "evidence_level", "count"])

    summary = {
        "schema": "s3.m22f.jsonext_source_bridge.v1",
        "generated_at_utc": utc_now(),
        "seed_jsonl": str(seed),
        "jsonext": str(jsonext),
        "json_mode": json_mode,
        "jsonext_extracted_vrp_source_records": len(extracted),
        "full_key_index_count": len(full_index),
        "loose_key_index_count": len(loose_index),
        "record_count": len(rows),
        "counters": dict(c),
        "tal_by_evidence_level": tal_evidence_rows,
        "repo_base_top20": repo.most_common(20),
        "roa_uri_top20": roa.most_common(20),
        "outputs": {
            "records_csv": str(records_csv),
            "records_jsonl": str(records_jsonl),
            "summary_json": str(summary_json),
            "summary_md": str(summary_md),
            "tal_by_evidence_level_csv": str(out / "dist_tal_by_evidence_level.csv"),
        },
        "semantic_boundary": "jsonext_current_snapshot_source_bridge_not_historical_causal_attribution",
        "next_stage": "M22G_REPOSITORY_ROA_CLUSTER_STATS_OR_EXPORT_MORE_JSONEXT_SIDECARS",
    }

    summary_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    md = []
    md.append("# M22F JSONEXT Source Bridge for TAL-stratified Sample")
    md.append("")
    md.append(f"- jsonext_extracted_vrp_source_records: `{len(extracted)}`")
    md.append(f"- full_key_index_count: `{len(full_index)}`")
    md.append(f"- loose_key_index_count: `{len(loose_index)}`")
    md.append(f"- record_count: `{len(rows)}`")
    md.append("")
    md.append("## Counters")
    for k, v in sorted(c.items()):
        md.append(f"- {k}: `{v}`")
    md.append("")
    md.append("## TAL by Evidence Level")
    for r in tal_evidence_rows:
        md.append(f"- {r['tal']} / {r['evidence_level']}: `{r['count']}`")
    md.append("")
    md.append("## Top Repo Base")
    for k, v in repo.most_common(20):
        md.append(f"- `{k}`: `{v}`")
    md.append("")
    md.append("## Interpretation")
    md.append("- ROA-level means the current JSONEXT snapshot contains a matching VRP source URI.")
    md.append("- Remaining VRP-only candidates may be historical, cache-trailing, or absent from the current JSONEXT snapshot.")
    md.append("- This is provenance mapping, not causal attribution.")
    summary_md.write_text("\n".join(md) + "\n", encoding="utf-8")

    check_txt.write_text(
        "\n".join([
            "M22F_JSONEXT_SOURCE_BRIDGE=PASS",
            f"generated_at_utc = {summary['generated_at_utc']}",
            f"jsonext_extracted_vrp_source_records = {len(extracted)}",
            f"full_key_index_count = {len(full_index)}",
            f"loose_key_index_count = {len(loose_index)}",
            f"record_count = {len(rows)}",
            f"summary_json = {summary_json}",
            f"summary_md = {summary_md}",
            f"records_csv = {records_csv}",
            f"records_jsonl = {records_jsonl}",
            "semantic_boundary = jsonext_current_snapshot_source_bridge_not_historical_causal_attribution",
            "next_stage = M22G_REPOSITORY_ROA_CLUSTER_STATS_OR_EXPORT_MORE_JSONEXT_SIDECARS",
            "",
        ]),
        encoding="utf-8",
    )

    print(check_txt.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
