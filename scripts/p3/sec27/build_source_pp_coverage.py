#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import gzip
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse


URI_RE = re.compile(r"^(rsync|https?)://([^/]+)(/.*)?$", re.IGNORECASE)


def open_text(path: Path):
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="ignore")
    return path.open("r", encoding="utf-8", errors="ignore")


def read_jsonl(path: Path):
    with open_text(path) as f:
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


def read_json_records(path: Path):
    name = path.name.lower()
    try:
        with open_text(path) as f:
            obj = json.load(f)
    except Exception:
        return

    if isinstance(obj, list):
        for x in obj:
            if isinstance(x, dict):
                yield x
        return

    if isinstance(obj, dict) and isinstance(obj.get("roas"), list):
        for x in obj["roas"]:
            if isinstance(x, dict):
                yield x
        return

    if isinstance(obj, dict):
        yield obj


def iter_records(path: Path):
    name = path.name.lower()
    if name.endswith(".jsonl") or name.endswith(".jsonl.gz"):
        yield from read_jsonl(path)
    elif name.endswith(".json") or name.endswith(".json.gz"):
        yield from read_json_records(path)


def infer_probe_id(path: Path) -> str:
    s = str(path)
    for p in ["probe-bj", "probe-cd", "probe-sg"]:
        if p in s:
            return p
    return ""


def infer_input_type(path: Path) -> str:
    s = str(path)
    name = path.name.lower()

    if "m21b_jsonext_selected_provenance_join.jsonl" in s:
        return "L3_M21B_SELECTED_PROVENANCE_JOIN"
    if "m21b_affected_vrp_provenance_mapping.jsonl" in s:
        return "L3_M21B_AFFECTED_PROVENANCE_MAPPING"
    if "vrp_provenance_index.jsonl.gz" in s:
        return "L3_VRP_PROVENANCE_INDEX"
    if "vrp_tuple_index.jsonl.gz" in s:
        return "L3_VRP_TUPLE_INDEX"
    if "vrps.jsonext.raw.json.gz" in s:
        return "L3_RAW_JSONEXT_GZ"

    if name.endswith("_notification.xml"):
        return "L1_RAW_NOTIFICATION_XML"

    if "active_manifest_records.jsonl" in s:
        return "L2_ACTIVE_MANIFEST_RECORDS"
    if "object_inventory.jsonl" in s:
        return "L2_OBJECT_INVENTORY"
    if "probe_raw_object_index.jsonl" in s:
        return "L2_RAW_OBJECT_INDEX"
    if "probe_missing_object_index.jsonl" in s:
        return "L2_MISSING_OBJECT_INDEX"
    if name.endswith(".mft") or "rsync__" in name:
        return "L2_RAW_MFT_WRAPPER_SAMPLE"

    return "OTHER"


def normalize_host(host: str) -> str:
    return (host or "").strip().lower().rstrip(".")


def parse_public_uri(uri: str) -> Tuple[str, str, str]:
    """
    Return: scheme, repo_host, repo_base.
    repo_base is directory-level URI ending with '/'.
    """
    if not isinstance(uri, str):
        return "", "", ""

    uri = uri.strip()
    m = URI_RE.match(uri)
    if not m:
        return "", "", ""

    scheme = m.group(1).lower()
    host = normalize_host(m.group(2))
    path = m.group(3) or "/"

    if "/" in path:
        base_path = path.rsplit("/", 1)[0] + "/"
    else:
        base_path = "/"

    return scheme, host, f"{scheme}://{host}{base_path}"


def parse_cache_uri(uri: str) -> Tuple[str, str, str]:
    """
    Parse cache URI/path examples:
      cache://rpki-cache/rsync/krill.ipgua.com/repo/pongery/0/x.mft
      cache://.rpki-cache/repository/rsync/rrdp.as214749.net/repo/as214749-paw/1/x.roa
      rsync/krill.ipgua.com/repo/pongery/0/x.mft
      /var/lib/routinator/rpki-cache/rsync/krill.ipgua.com/repo/pongery/0/x.mft
    """
    if not isinstance(uri, str):
        return "", "", ""

    s = uri.strip()

    # Remove cache:// prefix
    if s.startswith("cache://"):
        s = s[len("cache://"):]

    # Normalize separators
    parts = [x for x in s.split("/") if x]

    # Find rsync marker
    if "rsync" in parts:
        idx = parts.index("rsync")
        if idx + 1 < len(parts):
            host = normalize_host(parts[idx + 1])
            rest = parts[idx + 2:]
            if rest:
                base_rest = rest[:-1]
                repo_base = "rsync://" + host + "/" + "/".join(base_rest) + "/"
            else:
                repo_base = "rsync://" + host + "/"
            return "rsync", host, repo_base

    # Find rrdp/https marker if ever present
    for marker in ["https", "http"]:
        if marker in parts:
            idx = parts.index(marker)
            if idx + 1 < len(parts):
                host = normalize_host(parts[idx + 1])
                rest = parts[idx + 2:]
                scheme = marker
                if rest:
                    base_rest = rest[:-1]
                    repo_base = scheme + "://" + host + "/" + "/".join(base_rest) + "/"
                else:
                    repo_base = scheme + "://" + host + "/"
                return scheme, host, repo_base

    return "", "", ""


def parse_raw_mft_wrapper_path(path: Path) -> Tuple[str, str, str]:
    """
    Example:
    0001_rsync__krill.ipgua.com__repo__pongery__0__BDD...mft
    """
    name = path.name
    if "rsync__" not in name:
        return "", "", ""

    try:
        body = name.split("rsync__", 1)[1]
        parts = body.split("__")
        if not parts:
            return "", "", ""
        host = normalize_host(parts[0])
        # remove final filename/hash part
        repo_parts = parts[1:-1]
        repo_base = "rsync://" + host + "/"
        if repo_parts:
            repo_base += "/".join(repo_parts) + "/"
        return "rsync", host, repo_base
    except Exception:
        return "", "", ""


def extract_l3_sources_from_record(rec: Dict[str, Any], path: Path) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    input_type = infer_input_type(path)
    probe_id_from_path = infer_probe_id(path)

    def add(uri: str, tal: str = "", probe_id: str = "", vrp_key: str = ""):
        scheme, host, base = parse_public_uri(uri)
        if not host:
            return
        out.append({
            "source_uri": uri,
            "tal": (tal or rec.get("ta") or rec.get("tal") or "").lower(),
            "probe_id": probe_id or probe_id_from_path,
            "vrp_key": vrp_key or str(rec.get("vrp_key") or ""),
            "input_type": input_type,
        })

    # M21B selected join: source_uri_by_probe
    src_by_probe = rec.get("source_uri_by_probe")
    if isinstance(src_by_probe, dict):
        for probe_id, uris in src_by_probe.items():
            if isinstance(uris, list):
                for uri in uris:
                    if isinstance(uri, str):
                        add(uri, probe_id=str(probe_id))
            elif isinstance(uris, str):
                add(uris, probe_id=str(probe_id))

    # Routinator jsonext provenance index: source dict
    src = rec.get("source")
    if isinstance(src, dict):
        uri = src.get("uri")
        tal = src.get("tal") or rec.get("ta") or rec.get("tal") or ""
        if isinstance(uri, str):
            add(uri, tal=str(tal))

    # Routinator raw jsonext: source list
    if isinstance(src, list):
        for s in src:
            if isinstance(s, dict):
                uri = s.get("uri")
                tal = s.get("tal") or rec.get("ta") or rec.get("tal") or ""
                if isinstance(uri, str):
                    add(uri, tal=str(tal))

    # direct fields
    for key in ["source_uri", "roa_uri", "object_uri", "uri"]:
        uri = rec.get(key)
        if isinstance(uri, str):
            add(uri)

    return out


def parse_l1_notification(path: Path) -> List[Dict[str, str]]:
    out = []
    try:
        root = ET.parse(path).getroot()
    except Exception:
        return out

    session_id = root.attrib.get("session_id", "")
    serial = root.attrib.get("serial", "")

    # namespace-safe traversal
    for elem in root.iter():
        tag = elem.tag.split("}", 1)[-1]
        if tag not in {"snapshot", "delta"}:
            continue
        uri = elem.attrib.get("uri", "")
        scheme, host, base = parse_public_uri(uri)
        if not host:
            continue
        out.append({
            "uri": uri,
            "repo_host": host,
            "repo_base": base,
            "scheme": scheme,
            "session_id": session_id,
            "serial": serial,
            "kind": tag,
            "artifact": str(path),
        })
    return out


def extract_l2_from_record(rec: Dict[str, Any], path: Path) -> List[Dict[str, str]]:
    out = []
    input_type = infer_input_type(path)

    candidate_fields = [
        "uri",
        "object_uri",
        "source_uri",
        "roa_uri",
        "manifest_uri",
        "relative_path",
        "source_file",
    ]

    for key in candidate_fields:
        v = rec.get(key)
        if not isinstance(v, str) or not v:
            continue

        scheme, host, base = parse_public_uri(v)
        if not host:
            scheme, host, base = parse_cache_uri(v)

        if host:
            out.append({
                "repo_host": host,
                "repo_base": base,
                "scheme": scheme,
                "object_type": str(rec.get("object_type") or ""),
                "uri_like": v,
                "input_type": input_type,
                "artifact": str(path),
            })

    return out


def build_l1_index(paths: List[Path]) -> Dict[str, Any]:
    hosts = set()
    bases = set()
    samples = defaultdict(list)
    count = 0

    for p in paths:
        if infer_input_type(p) != "L1_RAW_NOTIFICATION_XML":
            continue
        for r in parse_l1_notification(p):
            count += 1
            h = r["repo_host"]
            b = r["repo_base"]
            hosts.add(h)
            bases.add(b)
            if len(samples[h]) < 5:
                samples[h].append(r["artifact"])

    return {
        "hosts": hosts,
        "bases": bases,
        "samples": samples,
        "record_count": count,
    }


def build_l2_index(paths: List[Path]) -> Dict[str, Any]:
    hosts = set()
    bases = set()
    samples = defaultdict(list)
    object_type_counter = Counter()
    record_count = 0
    parse_miss = Counter()

    for p in paths:
        t = infer_input_type(p)

        if t == "L2_RAW_MFT_WRAPPER_SAMPLE":
            scheme, host, base = parse_raw_mft_wrapper_path(p)
            if host:
                hosts.add(host)
                bases.add(base)
                record_count += 1
                object_type_counter["mft_wrapper"] += 1
                if len(samples[host]) < 5:
                    samples[host].append(str(p))
            else:
                parse_miss[t] += 1
            continue

        if t not in {
            "L2_ACTIVE_MANIFEST_RECORDS",
            "L2_OBJECT_INVENTORY",
            "L2_RAW_OBJECT_INDEX",
            "L2_MISSING_OBJECT_INDEX",
        }:
            continue

        for rec in iter_records(p):
            extracted = extract_l2_from_record(rec, p)
            if not extracted:
                parse_miss[t] += 1
                continue
            for r in extracted:
                record_count += 1
                h = r["repo_host"]
                b = r["repo_base"]
                hosts.add(h)
                bases.add(b)
                object_type_counter[r.get("object_type") or "unknown"] += 1
                if len(samples[h]) < 5:
                    samples[h].append(r["artifact"])

    return {
        "hosts": hosts,
        "bases": bases,
        "samples": samples,
        "record_count": record_count,
        "object_type_counter": object_type_counter,
        "parse_miss": parse_miss,
    }


def build_l3_source_index(paths: List[Path], include_raw_jsonext: bool = False) -> Dict[str, Any]:
    rows = {}
    seen_obs = set()
    no_source_uri_count = 0
    input_type_counter = Counter()
    tal_counter = Counter()
    source_uri_counter = Counter()

    for p in paths:
        t = infer_input_type(p)

        if t == "L3_VRP_TUPLE_INDEX":
            # tuple index has no source_uri; useful for no-source accounting only.
            # Do not process it as L3 source PP evidence.
            for _ in iter_records(p):
                no_source_uri_count += 1
            input_type_counter[t] += 1
            continue

        if t == "L3_RAW_JSONEXT_GZ" and not include_raw_jsonext:
            # provenance_index is preferred; raw jsonext is fallback only.
            continue

        if t not in {
            "L3_M21B_AFFECTED_PROVENANCE_MAPPING",
            "L3_M21B_SELECTED_PROVENANCE_JOIN",
            "L3_VRP_PROVENANCE_INDEX",
            "L3_RAW_JSONEXT_GZ",
        }:
            continue

        input_type_counter[t] += 1

        for rec in iter_records(p):
            srcs = extract_l3_sources_from_record(rec, p)
            if not srcs:
                no_source_uri_count += 1
                continue

            for s in srcs:
                uri = s["source_uri"]
                scheme, host, base = parse_public_uri(uri)
                if not host:
                    no_source_uri_count += 1
                    continue

                tal = s.get("tal", "")
                probe_id = s.get("probe_id", "")
                vrp_key = s.get("vrp_key", "")

                obs_key = (vrp_key, probe_id, uri, str(p))
                if obs_key in seen_obs:
                    continue
                seen_obs.add(obs_key)

                key = (host, base, tal)
                if key not in rows:
                    rows[key] = {
                        "repo_host": host,
                        "repo_base": base,
                        "tal": tal,
                        "l3_vrp_keys": set(),
                        "l3_source_uris": set(),
                        "l3_probe_ids": set(),
                        "l3_input_types": set(),
                        "sample_source_uri": uri,
                        "sample_artifacts": set(),
                        "l3_observation_count": 0,
                    }

                row = rows[key]
                if vrp_key:
                    row["l3_vrp_keys"].add(vrp_key)
                row["l3_source_uris"].add(uri)
                if probe_id:
                    row["l3_probe_ids"].add(probe_id)
                row["l3_input_types"].add(s.get("input_type", ""))
                row["sample_artifacts"].add(str(p))
                row["l3_observation_count"] += 1

                source_uri_counter[uri] += 1
                if tal:
                    tal_counter[tal] += 1

    return {
        "rows": rows,
        "no_source_uri_count": no_source_uri_count,
        "input_type_counter": input_type_counter,
        "tal_counter": tal_counter,
        "source_uri_counter": source_uri_counter,
    }


def coverage_status(l1_seen: bool, l2_seen: bool, l2b_seen: bool) -> Tuple[str, str]:
    if l1_seen and l2_seen and l2b_seen:
        return "COV_STRONG_L1_L2_L2B", "high"
    if l2_seen and l2b_seen:
        return "COV_L2_L2B", "medium-high"
    if l1_seen and l2b_seen:
        return "COV_L1_L2B", "medium"
    if l2b_seen:
        return "COV_L2B_ONLY", "medium"
    return "COV_NOT_COVERED_BY_CUSTOM_L1L2", "low"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--discovery-summary", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--paper-table-dir", required=True)
    ap.add_argument("--report", required=True)
    ap.add_argument("--include-raw-jsonext", action="store_true")
    args = ap.parse_args()

    summary_path = Path(args.discovery_summary)
    summary = json.loads(summary_path.read_text(encoding="utf-8"))

    out_dir = Path(args.out_dir)
    paper_dir = Path(args.paper_table_dir)
    report_path = Path(args.report)

    out_dir.mkdir(parents=True, exist_ok=True)
    paper_dir.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    l3_paths = [Path(p) for p in summary.get("recommended_primary_l3_inputs", []) if Path(p).exists()]
    l1_paths = [Path(p) for p in summary.get("recommended_primary_l1_inputs", []) if Path(p).exists()]
    l2_paths = [Path(p) for p in summary.get("recommended_primary_l2_inputs", []) if Path(p).exists()]

    l1 = build_l1_index(l1_paths)
    l2 = build_l2_index(l2_paths)
    l3 = build_l3_source_index(l3_paths, include_raw_jsonext=args.include_raw_jsonext)

    output_rows = []
    host_rollup = defaultdict(lambda: {
        "l3_vrp_keys": set(),
        "l3_source_uris": set(),
        "repo_bases": set(),
        "tal_set": set(),
        "l3_observation_count": 0,
        "covered_by_l1": False,
        "covered_by_l2": False,
        "covered_by_l2b": False,
    })

    for (host, base, tal), row in sorted(l3["rows"].items()):
        l1_seen = host in l1["hosts"] or base in l1["bases"]
        l2_seen = host in l2["hosts"] or base in l2["bases"]
        l2b_seen = bool(row["l3_source_uris"])

        status, confidence = coverage_status(l1_seen, l2_seen, l2b_seen)

        out = {
            "schema": "sec27.source_pp_coverage.v1",
            "repo_host": host,
            "repo_base": base,
            "tal": tal,
            "l3_vrp_count": len(row["l3_vrp_keys"]),
            "l3_roa_count": len(row["l3_source_uris"]),
            "l3_source_uri_count": len(row["l3_source_uris"]),
            "l3_observation_count": row["l3_observation_count"],
            "probe_count": len(row["l3_probe_ids"]),
            "probe_ids": ";".join(sorted(row["l3_probe_ids"])),
            "l3_input_types": ";".join(sorted(x for x in row["l3_input_types"] if x)),
            "l1_seen": l1_seen,
            "l2_seen": l2_seen,
            "l2b_seen": l2b_seen,
            "covered_by_l1": l1_seen,
            "covered_by_l2": l2_seen,
            "covered_by_l2b": l2b_seen,
            "coverage_status": status,
            "mapping_confidence": confidence,
            "sample_source_uri": row["sample_source_uri"],
            "sample_artifacts": ";".join(sorted(row["sample_artifacts"])[:5]),
        }
        output_rows.append(out)

        hr = host_rollup[host]
        hr["l3_vrp_keys"].update(row["l3_vrp_keys"])
        hr["l3_source_uris"].update(row["l3_source_uris"])
        hr["repo_bases"].add(base)
        if tal:
            hr["tal_set"].add(tal)
        hr["l3_observation_count"] += row["l3_observation_count"]
        hr["covered_by_l1"] = hr["covered_by_l1"] or l1_seen
        hr["covered_by_l2"] = hr["covered_by_l2"] or l2_seen
        hr["covered_by_l2b"] = hr["covered_by_l2b"] or l2b_seen

    jsonl_path = out_dir / "source_pp_coverage.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as f:
        for r in output_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    csv_path = paper_dir / "table_l3_source_pp_coverage.csv"
    fieldnames = [
        "repo_host",
        "repo_base",
        "tal",
        "l3_vrp_count",
        "l3_roa_count",
        "l3_source_uri_count",
        "l3_observation_count",
        "probe_count",
        "probe_ids",
        "l3_input_types",
        "covered_by_l1",
        "covered_by_l2",
        "covered_by_l2b",
        "coverage_status",
        "mapping_confidence",
        "sample_source_uri",
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in sorted(output_rows, key=lambda x: (-int(x["l3_observation_count"]), x["repo_host"], x["repo_base"])):
            w.writerow({k: r.get(k, "") for k in fieldnames})

    # host rollup table
    host_csv_path = paper_dir / "table_l3_source_host_coverage.csv"
    host_rows = []
    for host, hr in host_rollup.items():
        l1_seen = hr["covered_by_l1"]
        l2_seen = hr["covered_by_l2"]
        l2b_seen = hr["covered_by_l2b"]
        status, confidence = coverage_status(l1_seen, l2_seen, l2b_seen)
        host_rows.append({
            "repo_host": host,
            "tal_set": ";".join(sorted(hr["tal_set"])),
            "repo_base_count": len(hr["repo_bases"]),
            "l3_vrp_count": len(hr["l3_vrp_keys"]),
            "l3_source_uri_count": len(hr["l3_source_uris"]),
            "l3_observation_count": hr["l3_observation_count"],
            "covered_by_l1": l1_seen,
            "covered_by_l2": l2_seen,
            "covered_by_l2b": l2b_seen,
            "coverage_status": status,
            "mapping_confidence": confidence,
        })

    with host_csv_path.open("w", newline="", encoding="utf-8") as f:
        fields = [
            "repo_host",
            "tal_set",
            "repo_base_count",
            "l3_vrp_count",
            "l3_source_uri_count",
            "l3_observation_count",
            "covered_by_l1",
            "covered_by_l2",
            "covered_by_l2b",
            "coverage_status",
            "mapping_confidence",
        ]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in sorted(host_rows, key=lambda x: (-int(x["l3_observation_count"]), x["repo_host"])):
            w.writerow(r)

    # missing/parse summary
    missing_path = out_dir / "missing_field_summary.csv"
    with missing_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["category", "key", "count"])
        for k, v in sorted(l2["parse_miss"].items()):
            w.writerow(["l2_parse_miss", k, v])
        w.writerow(["l3_no_source_uri", "all", l3["no_source_uri_count"]])
        for k, v in sorted(l3["input_type_counter"].items()):
            w.writerow(["l3_input_type_file_count", k, v])

    status_counter = Counter(r["coverage_status"] for r in output_rows)
    host_status_counter = Counter(r["coverage_status"] for r in host_rows)

    top_uncovered = [
        r for r in sorted(host_rows, key=lambda x: -int(x["l3_observation_count"]))
        if not r["covered_by_l1"] and not r["covered_by_l2"]
    ][:30]

    report = {
        "schema": "sec27.source_pp_coverage_report.v1",
        "status": "PASS" if output_rows else "FAIL_NO_L3_SOURCE_ROWS",
        "discovery_summary": str(summary_path),
        "input_file_count": {
            "l3": len(l3_paths),
            "l1": len(l1_paths),
            "l2": len(l2_paths),
        },
        "l1_index": {
            "host_count": len(l1["hosts"]),
            "base_count": len(l1["bases"]),
            "record_count": l1["record_count"],
            "hosts_sample": sorted(l1["hosts"])[:20],
        },
        "l2_index": {
            "host_count": len(l2["hosts"]),
            "base_count": len(l2["bases"]),
            "record_count": l2["record_count"],
            "object_type_counter": dict(l2["object_type_counter"].most_common(30)),
            "parse_miss": dict(l2["parse_miss"]),
            "hosts_sample": sorted(l2["hosts"])[:20],
        },
        "l3_source_pp_count": len(output_rows),
        "l3_source_host_count": len(host_rows),
        "no_source_uri_count": l3["no_source_uri_count"],
        "coverage_status_by_repo_base": dict(status_counter),
        "coverage_status_by_repo_host": dict(host_status_counter),
        "covered_by_l1_count": sum(1 for r in output_rows if r["covered_by_l1"]),
        "covered_by_l2_count": sum(1 for r in output_rows if r["covered_by_l2"]),
        "covered_by_l2b_count": sum(1 for r in output_rows if r["covered_by_l2b"]),
        "not_covered_by_custom_l1l2_count": sum(1 for r in output_rows if not r["covered_by_l1"] and not r["covered_by_l2"]),
        "top_uncovered_repo_hosts": top_uncovered,
        "outputs": {
            "source_pp_coverage_jsonl": str(jsonl_path),
            "source_pp_coverage_csv": str(csv_path),
            "source_host_coverage_csv": str(host_csv_path),
            "missing_field_summary_csv": str(missing_path),
        },
        "notes": [
            "L2-b is approximated by Routinator jsonext/provenance source_uri presence.",
            "L1 is RRDP notification host coverage, mostly RIR notification endpoints.",
            "L2 coverage is derived from cache/object inventory and raw MFT wrapper paths.",
            "This report measures evidence coverage, not final root cause.",
        ],
    }

    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print("status =", report["status"])
    print("l3_source_pp_count =", report["l3_source_pp_count"])
    print("l3_source_host_count =", report["l3_source_host_count"])
    print("covered_by_l1_count =", report["covered_by_l1_count"])
    print("covered_by_l2_count =", report["covered_by_l2_count"])
    print("covered_by_l2b_count =", report["covered_by_l2b_count"])
    print("not_covered_by_custom_l1l2_count =", report["not_covered_by_custom_l1l2_count"])
    print("no_source_uri_count =", report["no_source_uri_count"])
    print("WROTE", jsonl_path)
    print("WROTE", csv_path)
    print("WROTE", host_csv_path)
    print("WROTE", report_path)


if __name__ == "__main__":
    main()
