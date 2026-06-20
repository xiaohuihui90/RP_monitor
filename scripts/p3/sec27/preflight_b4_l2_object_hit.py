#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlparse


def read_jsonl(path: Path):
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                yield obj


def write_jsonl(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def parse_public_uri(uri: str):
    if not isinstance(uri, str) or "://" not in uri:
        return "", "", ""
    p = urlparse(uri.strip())
    if not p.scheme or not p.netloc:
        return "", "", ""
    host = p.netloc.lower()
    path = p.path or "/"
    if path.endswith("/"):
        repo_base = f"{p.scheme.lower()}://{host}{path}"
        filename = ""
    else:
        repo_base = f"{p.scheme.lower()}://{host}{path.rsplit('/', 1)[0]}/"
        filename = path.rsplit("/", 1)[-1]
    return host, repo_base, filename


def cache_like_to_rsync_uri(value: str):
    if not isinstance(value, str):
        return ""

    s = value.strip()
    if not s:
        return ""

    if s.startswith("rsync://"):
        return s

    if s.startswith("cache://"):
        s = s[len("cache://"):]

    parts = [x for x in s.split("/") if x]

    if "rsync" not in parts:
        return ""

    i = parts.index("rsync")
    if i + 1 >= len(parts):
        return ""

    host = parts[i + 1].lower()
    rest = parts[i + 2:]
    if not rest:
        return f"rsync://{host}/"

    return "rsync://" + host + "/" + "/".join(rest)


def infer_l2_type(path: Path):
    s = str(path)
    if "object_inventory.jsonl" in s:
        return "L2_OBJECT_INVENTORY"
    if "active_manifest_records.jsonl" in s:
        return "L2_ACTIVE_MANIFEST_RECORDS"
    if "probe_raw_object_index.jsonl" in s:
        return "L2_RAW_OBJECT_INDEX"
    if "probe_missing_object_index.jsonl" in s:
        return "L2_MISSING_OBJECT_INDEX"
    return "OTHER"


def load_l2_paths(discovery_summary: Path):
    s = json.loads(discovery_summary.read_text(encoding="utf-8"))
    paths = []

    for p in s.get("recommended_primary_l2_inputs", []):
        pp = Path(p)
        if not pp.exists():
            continue

        t = infer_l2_type(pp)
        if t in {
            "L2_OBJECT_INVENTORY",
            "L2_ACTIVE_MANIFEST_RECORDS",
            "L2_RAW_OBJECT_INDEX",
            "L2_MISSING_OBJECT_INDEX",
        }:
            paths.append(pp)

    return paths


def extract_l2_candidate_uris(record: dict):
    vals = []

    for k in [
        "uri",
        "object_uri",
        "source_uri",
        "roa_uri",
        "relative_path",
        "source_file",
    ]:
        v = record.get(k)
        if isinstance(v, str):
            u = cache_like_to_rsync_uri(v)
            if u:
                vals.append(u)

    return vals


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--l2b", required=True)
    ap.add_argument("--discovery-summary", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--paper-table-dir", required=True)
    ap.add_argument("--report", required=True)
    args = ap.parse_args()

    l2b_path = Path(args.l2b)
    discovery_summary = Path(args.discovery_summary)
    out_dir = Path(args.out_dir)
    paper_dir = Path(args.paper_table_dir)
    report_path = Path(args.report)

    out_dir.mkdir(parents=True, exist_ok=True)
    paper_dir.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    target_by_uri = {}
    target_hosts = Counter()
    target_tals = Counter()
    target_vrp_keys_by_uri = defaultdict(set)

    for r in read_jsonl(l2b_path):
        uri = r.get("source_uri")
        if not uri:
            continue

        host, repo_base, filename = parse_public_uri(uri)
        if not host:
            continue

        target_by_uri[uri] = {
            "source_uri": uri,
            "repo_host": host,
            "repo_base": repo_base,
            "filename": filename,
            "tal": r.get("tal"),
            "evidence_level": r.get("evidence_level"),
            "temporal_alignment_quality": r.get("temporal_alignment_quality"),
        }

        if r.get("vrp_key"):
            target_vrp_keys_by_uri[uri].add(str(r.get("vrp_key")))

        target_hosts[host] += 1
        if r.get("tal"):
            target_tals[str(r.get("tal"))] += 1

    target_uris = set(target_by_uri.keys())

    hit_by_uri = defaultdict(list)
    scanned_records = 0
    scanned_files = 0
    l2_type_counter = Counter()
    object_type_counter = Counter()

    l2_paths = load_l2_paths(discovery_summary)

    for p in l2_paths:
        scanned_files += 1
        l2_type = infer_l2_type(p)
        l2_type_counter[l2_type] += 1

        for rec in read_jsonl(p):
            scanned_records += 1
            object_type = str(rec.get("object_type") or "")
            sha256 = str(rec.get("sha256") or "")

            for u in extract_l2_candidate_uris(rec):
                if u in target_uris:
                    hit_by_uri[u].append({
                        "l2_input_type": l2_type,
                        "object_type": object_type,
                        "sha256": sha256,
                        "artifact": str(p),
                    })
                    if object_type:
                        object_type_counter[object_type] += 1

    rows = []
    for uri, base in sorted(target_by_uri.items()):
        hits = hit_by_uri.get(uri, [])
        rows.append({
            "schema": "sec27.b4a_l2_object_hit.v1",
            **base,
            "vrp_key_count": len(target_vrp_keys_by_uri.get(uri, set())),
            "l2_object_hit": bool(hits),
            "l2_hit_count": len(hits),
            "l2_object_types": ";".join(sorted({h.get("object_type", "") for h in hits if h.get("object_type")})),
            "l2_sha256_sample": hits[0].get("sha256") if hits else "",
            "l2_artifact_sample": hits[0].get("artifact") if hits else "",
        })

    jsonl_path = out_dir / "b4a_l2_object_hit.jsonl"
    write_jsonl(jsonl_path, rows)

    csv_path = paper_dir / "table_b4a_l2_object_hit_summary.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["section", "value", "count"])
        w.writerow(["overall", "target_source_uri_count", len(target_by_uri)])
        w.writerow(["overall", "hit_source_uri_count", sum(1 for r in rows if r["l2_object_hit"])])
        w.writerow(["overall", "miss_source_uri_count", sum(1 for r in rows if not r["l2_object_hit"])])
        w.writerow(["overall", "scanned_l2_files", scanned_files])
        w.writerow(["overall", "scanned_l2_records", scanned_records])

        for k, v in target_hosts.most_common(30):
            w.writerow(["target_repo_host", k, v])
        for k, v in target_tals.most_common():
            w.writerow(["target_tal", k, v])
        for k, v in l2_type_counter.most_common():
            w.writerow(["l2_input_type", k, v])
        for k, v in object_type_counter.most_common():
            w.writerow(["hit_object_type", k, v])

    miss_rows = [r for r in rows if not r["l2_object_hit"]]
    miss_path = out_dir / "b4a_l2_object_miss.jsonl"
    write_jsonl(miss_path, miss_rows)

    status = "PASS" if rows else "FAIL_NO_TARGET_SOURCE_URI"

    report = {
        "schema": "sec27.b4a_l2_object_hit_report.v1",
        "status": status,
        "input_l2b": str(l2b_path),
        "discovery_summary": str(discovery_summary),
        "target_source_uri_count": len(target_by_uri),
        "hit_source_uri_count": sum(1 for r in rows if r["l2_object_hit"]),
        "miss_source_uri_count": sum(1 for r in rows if not r["l2_object_hit"]),
        "hit_ratio": (
            sum(1 for r in rows if r["l2_object_hit"]) / len(rows)
            if rows else 0.0
        ),
        "scanned_l2_files": scanned_files,
        "scanned_l2_records": scanned_records,
        "target_repo_host_top": target_hosts.most_common(30),
        "target_tal_distribution": dict(target_tals),
        "l2_input_type_distribution": dict(l2_type_counter),
        "hit_object_type_distribution": dict(object_type_counter),
        "outputs": {
            "b4a_l2_object_hit_jsonl": str(jsonl_path),
            "b4a_l2_object_miss_jsonl": str(miss_path),
            "summary_csv": str(csv_path),
            "report": str(report_path),
        },
        "notes": [
            "B4A checks whether L2-b source_uri ROA objects can be found in L2 object inventory/raw object indexes.",
            "This is exact URI hit only after normalizing cache://.../rsync/... to rsync://...",
            "This preflight does not yet parse manifest fileList or verify manifest hash.",
            "B4A is a gate before building the full attribution chain.",
        ],
    }

    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

    print("status =", report["status"])
    print("target_source_uri_count =", report["target_source_uri_count"])
    print("hit_source_uri_count =", report["hit_source_uri_count"])
    print("miss_source_uri_count =", report["miss_source_uri_count"])
    print("hit_ratio =", report["hit_ratio"])
    print("scanned_l2_files =", report["scanned_l2_files"])
    print("scanned_l2_records =", report["scanned_l2_records"])
    print("target_tal_distribution =", report["target_tal_distribution"])
    print("WROTE", jsonl_path)
    print("WROTE", miss_path)
    print("WROTE", csv_path)
    print("WROTE", report_path)


if __name__ == "__main__":
    main()
