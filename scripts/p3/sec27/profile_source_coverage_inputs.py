#!/usr/bin/env python3
import argparse
import gzip
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


URI_RE = re.compile(r"^(rsync|https?)://([^/]+)(/.*)?$", re.IGNORECASE)


def open_text(path: Path):
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="ignore")
    return path.open("r", encoding="utf-8", errors="ignore")


def load_json_or_jsonl(path: Path, max_records: int = 200) -> List[Dict[str, Any]]:
    records = []
    name = path.name.lower()

    try:
        if name.endswith(".jsonl") or name.endswith(".jsonl.gz"):
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
                        records.append(obj)
                    if len(records) >= max_records:
                        break
            return records

        if name.endswith(".json") or name.endswith(".json.gz"):
            with open_text(path) as f:
                obj = json.load(f)

            if isinstance(obj, list):
                for x in obj[:max_records]:
                    if isinstance(x, dict):
                        records.append(x)
                return records

            if isinstance(obj, dict):
                # Routinator jsonext 常见 roas 字段
                if isinstance(obj.get("roas"), list):
                    for x in obj["roas"][:max_records]:
                        if isinstance(x, dict):
                            records.append(x)
                    return records

                # 其他 summary / manifest 类型先保留整个 dict
                records.append(obj)
                return records

    except Exception as e:
        return [{"__profile_error__": repr(e)}]

    return records


def flatten_keys(obj: Dict[str, Any], prefix: str = "", depth: int = 0, max_depth: int = 2) -> List[str]:
    keys = []
    if depth > max_depth:
        return keys
    for k, v in obj.items():
        kk = f"{prefix}.{k}" if prefix else str(k)
        keys.append(kk)
        if isinstance(v, dict):
            keys.extend(flatten_keys(v, kk, depth + 1, max_depth))
        elif isinstance(v, list) and v and isinstance(v[0], dict):
            keys.extend(flatten_keys(v[0], kk + "[]", depth + 1, max_depth))
    return keys


def extract_candidate_uris(obj: Dict[str, Any]) -> List[str]:
    uris = []

    # 常见直接字段
    for k in ["source_uri", "roa_uri", "object_uri", "uri", "rsync_uri", "rrdp_uri", "manifest_uri"]:
        v = obj.get(k)
        if isinstance(v, str) and URI_RE.match(v):
            uris.append(v)

    # Routinator jsonext source / sources
    src = obj.get("source")
    if isinstance(src, dict):
        v = src.get("uri")
        if isinstance(v, str) and URI_RE.match(v):
            uris.append(v)
    elif isinstance(src, list):
        for s in src:
            if isinstance(s, dict):
                v = s.get("uri")
                if isinstance(v, str) and URI_RE.match(v):
                    uris.append(v)

    sources = obj.get("sources")
    if isinstance(sources, list):
        for s in sources:
            if isinstance(s, dict):
                v = s.get("uri")
                if isinstance(v, str) and URI_RE.match(v):
                    uris.append(v)

    # 嵌套 raw jsonext 可能在 provenance 里
    prov = obj.get("provenance")
    if isinstance(prov, dict):
        v = prov.get("source_uri") or prov.get("uri")
        if isinstance(v, str) and URI_RE.match(v):
            uris.append(v)

    return sorted(set(uris))


def parse_repo(uri: str) -> Tuple[str, str]:
    m = URI_RE.match(uri)
    if not m:
        return "", ""
    host = m.group(2).lower()
    path = m.group(3) or ""
    # repo_base 先保守取目录，不解析文件名
    if "/" in path:
        base = path.rsplit("/", 1)[0] + "/"
    else:
        base = path
    return host, f"{m.group(1).lower()}://{host}{base}"


def infer_type(path: Path) -> str:
    s = str(path)
    name = path.name.lower()
    if "vrp_provenance_index.jsonl.gz" in s:
        return "L3_VRP_PROVENANCE_INDEX"
    if "vrp_tuple_index.jsonl.gz" in s:
        return "L3_VRP_TUPLE_INDEX"
    if "vrps.jsonext.raw.json.gz" in s:
        return "L3_RAW_JSONEXT_GZ"
    if "m21b_jsonext_selected_provenance_join.jsonl" in s:
        return "L3_M21B_SELECTED_PROVENANCE_JOIN"
    if "m21b_affected_vrp_provenance_mapping.jsonl" in s:
        return "L3_M21B_AFFECTED_PROVENANCE_MAPPING"
    if name.endswith("_notification.xml"):
        return "L1_RAW_NOTIFICATION_XML"
    if "active_manifest_records.jsonl" in s:
        return "L2_ACTIVE_MANIFEST_RECORDS"
    if "object_inventory.jsonl" in s:
        return "L2_OBJECT_INVENTORY"
    if "probe_raw_object_index.jsonl" in s:
        return "L2_RAW_OBJECT_INDEX"
    if name.endswith(".mft") or "rsync__" in name:
        return "L2_RAW_MFT_WRAPPER_SAMPLE"
    return "OTHER"


def path_based_host(path: Path) -> Tuple[str, str]:
    name = path.name

    # 兼容 raw wrapper: 0001_rsync__host__repo__xxx.mft
    if "rsync__" in name:
        parts = name.split("__")
        try:
            idx = parts.index("rsync")
        except ValueError:
            idx = -1
        if idx >= 0 and idx + 1 < len(parts):
            host = parts[idx + 1].lower()
            repo_base = "rsync://" + host + "/" + "/".join(parts[idx + 2:-1]) + "/"
            return host, repo_base

    return "", ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--summary", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--max-files-per-type", type=int, default=5)
    ap.add_argument("--max-records-per-file", type=int, default=200)
    args = ap.parse_args()

    summary_path = Path(args.summary)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = json.loads(summary_path.read_text(encoding="utf-8"))

    paths = []
    for key in ["recommended_primary_l3_inputs", "recommended_primary_l1_inputs", "recommended_primary_l2_inputs"]:
        for p in summary.get(key, []):
            paths.append(Path(p))

    by_type = defaultdict(list)
    for p in paths:
        by_type[infer_type(p)].append(p)

    profiles = []
    type_counts = {}
    host_counter = Counter()
    uri_counter = Counter()
    missing_or_unparsed = Counter()

    for t, plist in sorted(by_type.items()):
        type_counts[t] = len(plist)
        for p in plist[: args.max_files_per_type]:
            recs = load_json_or_jsonl(p, max_records=args.max_records_per_file)
            key_counter = Counter()
            uri_sample = []
            host_sample = []

            if not recs and infer_type(p) == "L2_RAW_MFT_WRAPPER_SAMPLE":
                h, b = path_based_host(p)
                if h:
                    host_counter[h] += 1
                    host_sample.append(h)

            for r in recs:
                if not isinstance(r, dict):
                    continue
                for k in flatten_keys(r):
                    key_counter[k] += 1

                uris = extract_candidate_uris(r)
                if not uris:
                    missing_or_unparsed[t] += 1

                for u in uris:
                    uri_counter[u] += 1
                    h, b = parse_repo(u)
                    if h:
                        host_counter[h] += 1
                        host_sample.append(h)
                    if len(uri_sample) < 10:
                        uri_sample.append(u)

            profiles.append({
                "type": t,
                "path": str(p),
                "record_sample_count": len(recs),
                "top_keys": key_counter.most_common(40),
                "uri_sample": uri_sample[:10],
                "host_sample": sorted(set(host_sample))[:10],
            })

    report = {
        "schema": "sec27.discovery.input_profile.v1",
        "summary_path": str(summary_path),
        "type_counts": type_counts,
        "profiled_file_count": len(profiles),
        "top_hosts": host_counter.most_common(50),
        "top_uris": uri_counter.most_common(20),
        "missing_or_unparsed_by_type": dict(missing_or_unparsed),
        "profiles": profiles,
        "notes": [
            "This preflight only profiles field names and URI availability.",
            "It does not compute final coverage.",
            "L2 raw MFT wrapper samples are path-parsed only in this stage.",
        ],
    }

    out_json = out_dir / "sec27_b2_input_schema_profile.json"
    out_txt = out_dir / "sec27_b2_input_schema_profile.txt"

    out_json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    with out_txt.open("w", encoding="utf-8") as f:
        f.write("SEC27-B2 INPUT SCHEMA PROFILE\n\n")
        f.write("TYPE COUNTS\n")
        for k, v in sorted(type_counts.items()):
            f.write(f"{k}: {v}\n")
        f.write("\nTOP HOSTS\n")
        for h, c in report["top_hosts"][:30]:
            f.write(f"{h}\t{c}\n")
        f.write("\nMISSING_OR_UNPARSED_BY_TYPE\n")
        for k, v in sorted(report["missing_or_unparsed_by_type"].items()):
            f.write(f"{k}: {v}\n")
        f.write("\nPROFILES\n")
        for p in profiles:
            f.write("\n---\n")
            f.write(f"type: {p['type']}\n")
            f.write(f"path: {p['path']}\n")
            f.write(f"record_sample_count: {p['record_sample_count']}\n")
            f.write("top_keys:\n")
            for k, c in p["top_keys"][:25]:
                f.write(f"  {k}: {c}\n")
            f.write("uri_sample:\n")
            for u in p["uri_sample"][:5]:
                f.write(f"  {u}\n")
            f.write("host_sample:\n")
            for h in p["host_sample"][:5]:
                f.write(f"  {h}\n")

    print("WROTE", out_json)
    print("WROTE", out_txt)
    print("type_counts =", json.dumps(type_counts, indent=2, ensure_ascii=False))
    print("top_hosts =", report["top_hosts"][:20])


if __name__ == "__main__":
    main()
