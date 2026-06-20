#!/usr/bin/env python3
import argparse
import gzip
import json
from pathlib import Path
from collections import defaultdict


def open_text(path: Path):
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="ignore")
    return path.open("r", encoding="utf-8", errors="ignore")


def read_records(path: Path, max_records: int = 5):
    name = path.name.lower()

    try:
        if name.endswith(".jsonl") or name.endswith(".jsonl.gz"):
            out = []
            with open_text(path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception as e:
                        out.append({"__parse_error__": repr(e), "__raw__": line[:300]})
                        continue
                    out.append(obj)
                    if len(out) >= max_records:
                        break
            return out

        if name.endswith(".json") or name.endswith(".json.gz"):
            with open_text(path) as f:
                obj = json.load(f)

            if isinstance(obj, dict) and isinstance(obj.get("roas"), list):
                return obj["roas"][:max_records]

            if isinstance(obj, list):
                return obj[:max_records]

            return [obj]

        if name.endswith(".xml"):
            txt = path.read_text(encoding="utf-8", errors="ignore")
            return [{"__xml_head__": txt[:1500]}]

        # raw mft / other binary-like file: only path info
        return [{"__path_only__": str(path), "__name__": path.name}]

    except Exception as e:
        return [{"__read_error__": repr(e), "__path__": str(path)}]


def infer_type(path: Path):
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
    if name.endswith(".mft") or "rsync__" in name:
        return "L2_RAW_MFT_WRAPPER_SAMPLE"

    return "OTHER"


def compact_obj(obj):
    if not isinstance(obj, dict):
        return obj

    keys = [
        "schema",
        "probe_id",
        "window_id",
        "vrp_key",
        "asn",
        "asn_id",
        "prefix",
        "maxLength",
        "max_length",
        "ta",
        "tal",
        "uri",
        "source_uri",
        "roa_uri",
        "object_uri",
        "source",
        "sources",
        "source_uri_by_probe",
        "source_root",
        "source_file",
        "relative_path",
        "object_type",
        "sha256",
        "size_bytes",
        "manifest_uri",
        "manifestNumber",
        "thisUpdate",
        "nextUpdate",
    ]

    out = {}
    for k in keys:
        if k in obj:
            out[k] = obj[k]

    if not out:
        # 保留前 20 个键，避免输出过大
        for i, (k, v) in enumerate(obj.items()):
            if i >= 20:
                break
            out[k] = v

    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--summary", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-files-per-type", type=int, default=3)
    ap.add_argument("--max-records-per-file", type=int, default=5)
    args = ap.parse_args()

    summary = json.loads(Path(args.summary).read_text(encoding="utf-8"))

    paths = []
    for key in [
        "recommended_primary_l3_inputs",
        "recommended_primary_l1_inputs",
        "recommended_primary_l2_inputs",
    ]:
        paths.extend(summary.get(key, []))

    by_type = defaultdict(list)
    for p in paths:
        pp = Path(p)
        if pp.exists():
            by_type[infer_type(pp)].append(pp)

    report = {
        "schema": "sec27.b2a_r1.field_drilldown.v1",
        "summary": str(args.summary),
        "types": {},
    }

    for t, plist in sorted(by_type.items()):
        selected = plist[: args.max_files_per_type]
        report["types"][t] = []
        for p in selected:
            recs = read_records(p, max_records=args.max_records_per_file)
            report["types"][t].append({
                "path": str(p),
                "record_count_sampled": len(recs),
                "records": [compact_obj(x) for x in recs],
            })

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print("WROTE", out)
    print("types =", sorted(report["types"].keys()))
    for t, items in report["types"].items():
        print(t, len(items))


if __name__ == "__main__":
    main()
