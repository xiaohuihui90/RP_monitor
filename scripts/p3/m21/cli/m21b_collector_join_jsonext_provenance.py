#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import tarfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def open_jsonl_gz(path: Path):
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def norm_asn(v: Any) -> int:
    s = str(v).strip().upper()
    if s.startswith("AS"):
        s = s[2:]
    return int(s)


def vrp_key(asn: Any, prefix: Any, max_length: Any, ta: Any) -> str:
    obj = {
        "asn": norm_asn(asn),
        "prefix": str(prefix).strip(),
        "max_length": int(max_length),
        "ta": str(ta).strip().lower(),
    }
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def row_to_vrp_key(row: Dict[str, Any]) -> str:
    return vrp_key(
        row.get("asn") or row.get("asID") or row.get("as_id"),
        row.get("prefix"),
        row.get("max_length", row.get("maxLength")),
        row.get("ta") or row.get("tal"),
    )


def verify_sha256_file(sha_file: Path) -> Dict[str, Any]:
    text = sha_file.read_text(encoding="utf-8").strip()
    expected = text.split()[0]
    archive_name = text.split()[1] if len(text.split()) > 1 else sha_file.name.replace(".sha256", "")
    archive_path = sha_file.parent / Path(archive_name).name

    h = hashlib.sha256()
    with archive_path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    actual = h.hexdigest()

    return {
        "sha_file": str(sha_file),
        "archive_path": str(archive_path),
        "expected": expected,
        "actual": actual,
        "ok": expected == actual,
    }


def safe_extract_tar(tar_path: Path, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tar_path, "r:gz") as tar:
        members = tar.getmembers()
        for m in members:
            target = dest / m.name
            if not str(target.resolve()).startswith(str(dest.resolve())):
                raise RuntimeError(f"unsafe tar member: {m.name}")
        tar.extractall(dest)

    top_dirs = sorted([p for p in dest.iterdir() if p.is_dir()], key=lambda p: p.name)
    matching = [p for p in top_dirs if p.name in tar_path.name]
    if matching:
        return matching[0]
    if len(top_dirs) == 1:
        return top_dirs[0]

    candidates = list(dest.glob("m21b_jsonext_joint_probe-*"))
    if candidates:
        return sorted(candidates)[-1]

    raise FileNotFoundError(f"cannot locate extracted run dir for {tar_path}")


def find_one(root: Path, pattern: str) -> Path:
    matches = sorted(root.glob(pattern))
    if not matches:
        raise FileNotFoundError(f"missing {pattern} under {root}")
    return matches[0]


def load_probe_archive(archive_path: Path, extract_root: Path) -> Dict[str, Any]:
    probe_extract_dir = extract_root / archive_path.stem.replace(".tar", "")
    if probe_extract_dir.exists():
        # keep existing extracted result if present
        pass
    run_dir = safe_extract_tar(archive_path, probe_extract_dir)

    summary_path = find_one(run_dir, "outputs/M21B_probe_jsonext_joint_snapshot_summary.json")
    tuple_index = find_one(run_dir, "indexes/vrp_tuple_index.jsonl.gz")
    provenance_index = find_one(run_dir, "indexes/vrp_provenance_index.jsonl.gz")

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    probe_id = summary.get("probe_id")
    if not probe_id:
        raise RuntimeError(f"summary missing probe_id: {summary_path}")

    return {
        "probe_id": probe_id,
        "run_id": summary.get("run_id"),
        "target_utc": summary.get("target_utc"),
        "status": summary.get("status"),
        "export_status": summary.get("export_status"),
        "summary": summary,
        "run_dir": str(run_dir),
        "summary_path": str(summary_path),
        "tuple_index": str(tuple_index),
        "provenance_index": str(provenance_index),
    }


def load_tuple_map(tuple_index: Path) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for row in open_jsonl_gz(tuple_index):
        key = row.get("vrp_key")
        if not key:
            key = row_to_vrp_key(row)
        out[key] = row
    return out


def load_affected_set(path: Path | None) -> Dict[str, Dict[str, Any]]:
    if not path or not path.exists():
        return {}

    out: Dict[str, Dict[str, Any]] = {}
    with path.open("rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            key = row.get("vrp_key")
            if not key:
                key = row_to_vrp_key(row)
            out[key] = {
                "vrp_key": key,
                "asn": norm_asn(row.get("asn") or row.get("asID") or row.get("as_id")),
                "prefix": str(row.get("prefix")).strip(),
                "max_length": int(row.get("max_length", row.get("maxLength"))),
                "ta": str(row.get("ta") or row.get("tal")).strip().lower(),
                "raw": row,
            }
    return out


def pair_name(a: str, b: str) -> str:
    return f"{a}_vs_{b}"


def main() -> int:
    ap = argparse.ArgumentParser(description="M21-B3 collector-side JSONEXT tuple/provenance join")
    ap.add_argument("--import-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--affected-vrp-set", default="")
    args = ap.parse_args()

    import_dir = Path(args.import_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    extract_root = out_dir / "extracted"
    indexes_dir = out_dir / "indexes"
    outputs_dir = out_dir / "outputs"
    checks_dir = out_dir / "checks"

    for d in [extract_root, indexes_dir, outputs_dir, checks_dir]:
        d.mkdir(parents=True, exist_ok=True)

    archives = sorted(import_dir.glob("m21b_jsonext_joint_probe-*.tar.gz"))
    sha_files = sorted(import_dir.glob("m21b_jsonext_joint_probe-*.tar.gz.sha256"))

    if len(archives) != 3:
        raise RuntimeError(f"expected 3 archives, got {len(archives)}: {[p.name for p in archives]}")

    sha_results = [verify_sha256_file(p) for p in sha_files]
    bad_sha = [r for r in sha_results if not r["ok"]]
    if bad_sha:
        raise RuntimeError(f"sha256 verify failed: {bad_sha}")

    probe_infos = []
    for archive in archives:
        probe_infos.append(load_probe_archive(archive, extract_root))

    probe_infos = sorted(probe_infos, key=lambda x: x["probe_id"])
    probe_ids = [x["probe_id"] for x in probe_infos]

    tuple_maps: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for info in probe_infos:
        tuple_maps[info["probe_id"]] = load_tuple_map(Path(info["tuple_index"]))

    tuple_sets = {p: set(m.keys()) for p, m in tuple_maps.items()}
    global_union = set().union(*tuple_sets.values())
    global_intersection = set.intersection(*tuple_sets.values())

    pairwise = {}
    for i, a in enumerate(probe_ids):
        for b in probe_ids[i + 1:]:
            only_a = tuple_sets[a] - tuple_sets[b]
            only_b = tuple_sets[b] - tuple_sets[a]
            inter = tuple_sets[a] & tuple_sets[b]
            union = tuple_sets[a] | tuple_sets[b]
            pairwise[pair_name(a, b)] = {
                "only_left": len(only_a),
                "only_right": len(only_b),
                "symdiff": len(only_a) + len(only_b),
                "intersection": len(inter),
                "union": len(union),
                "jaccard": (len(inter) / len(union)) if union else 1.0,
            }

    affected_path = Path(args.affected_vrp_set).resolve() if args.affected_vrp_set else None
    affected = load_affected_set(affected_path)
    affected_keys = set(affected.keys())

    diff_keys = global_union - global_intersection
    selected_keys = set(diff_keys) | affected_keys

    selected_provenance: Dict[str, Dict[str, list]] = {
        key: {p: [] for p in probe_ids}
        for key in selected_keys
    }

    # Stream provenance indexes only for selected keys.
    for info in probe_infos:
        probe_id = info["probe_id"]
        for row in open_jsonl_gz(Path(info["provenance_index"])):
            key = row.get("vrp_key")
            if key in selected_provenance:
                selected_provenance[key][probe_id].append(row)

    # Write global diff records.
    diff_path = indexes_dir / "m21b_jsonext_tuple_presence_diff.jsonl"
    with diff_path.open("wt", encoding="utf-8") as out:
        for key in sorted(diff_keys):
            present = [p for p in probe_ids if key in tuple_sets[p]]
            absent = [p for p in probe_ids if key not in tuple_sets[p]]
            sample_row = None
            for p in present:
                sample_row = tuple_maps[p][key]
                break
            row = {
                "schema": "s3.m21b.collector_jsonext_tuple_presence_diff.v1",
                "vrp_key": key,
                "present_probes": present,
                "absent_probes": absent,
                "present_probe_count": len(present),
                "absent_probe_count": len(absent),
                "sample_tuple": sample_row,
                "is_affected_input": key in affected,
            }
            out.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    # Write selected provenance join records.
    selected_join_path = indexes_dir / "m21b_jsonext_selected_provenance_join.jsonl"
    affected_mapping_path = outputs_dir / "m21b_affected_vrp_provenance_mapping.jsonl"

    affected_presence_counter = Counter()
    affected_ta_counter = Counter()
    affected_with_any_provenance = 0
    affected_all_probe_present = 0
    affected_some_missing = 0
    affected_absent_all = 0

    with selected_join_path.open("wt", encoding="utf-8") as all_out, affected_mapping_path.open("wt", encoding="utf-8") as aff_out:
        for key in sorted(selected_keys):
            present = [p for p in probe_ids if key in tuple_sets[p]]
            absent = [p for p in probe_ids if key not in tuple_sets[p]]
            prov_by_probe = selected_provenance.get(key, {p: [] for p in probe_ids})
            source_uri_by_probe = {}
            validity_by_probe = {}
            chain_validity_by_probe = {}
            stale_by_probe = {}

            for p in probe_ids:
                uris = []
                vals = []
                chains = []
                stales = []
                for r in prov_by_probe.get(p, []):
                    src = r.get("source", {}) or {}
                    if src.get("uri"):
                        uris.append(src.get("uri"))
                    if src.get("validity") is not None:
                        vals.append(src.get("validity"))
                    if src.get("chainValidity") is not None:
                        chains.append(src.get("chainValidity"))
                    if src.get("stale") is not None:
                        stales.append(src.get("stale"))
                source_uri_by_probe[p] = sorted(set(uris))
                validity_by_probe[p] = sorted(set(map(str, vals)))
                chain_validity_by_probe[p] = sorted(set(map(str, chains)))
                stale_by_probe[p] = sorted(set(map(str, stales)))

            tuple_sample = None
            for p in present:
                tuple_sample = tuple_maps[p][key]
                break

            row = {
                "schema": "s3.m21b.collector_jsonext_selected_provenance_join.v1",
                "vrp_key": key,
                "is_global_presence_diff": key in diff_keys,
                "is_affected_input": key in affected,
                "affected_input": affected.get(key),
                "present_probes": present,
                "absent_probes": absent,
                "present_probe_count": len(present),
                "absent_probe_count": len(absent),
                "tuple_by_probe": {p: tuple_maps[p].get(key) for p in probe_ids},
                "source_uri_by_probe": source_uri_by_probe,
                "validity_by_probe": validity_by_probe,
                "chain_validity_by_probe": chain_validity_by_probe,
                "stale_by_probe": stale_by_probe,
                "provenance_count_by_probe": {p: len(prov_by_probe.get(p, [])) for p in probe_ids},
                "sample_tuple": tuple_sample,
            }
            all_out.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            if key in affected:
                aff_out.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

                affected_ta_counter[affected[key]["ta"]] += 1
                affected_presence_counter[str(len(present))] += 1
                if any(len(prov_by_probe.get(p, [])) > 0 for p in probe_ids):
                    affected_with_any_provenance += 1
                if len(present) == len(probe_ids):
                    affected_all_probe_present += 1
                elif len(present) == 0:
                    affected_absent_all += 1
                else:
                    affected_some_missing += 1

    summary = {
        "schema": "s3.m21b.collector_jsonext_join_summary.v1",
        "status": "PASS",
        "created_at_utc": utc_now_iso(),
        "import_dir": str(import_dir),
        "out_dir": str(out_dir),
        "archive_count": len(archives),
        "sha256_verified_count": len(sha_results),
        "probe_ids": probe_ids,
        "target_utc_values": sorted(set(i["target_utc"] for i in probe_infos)),
        "probe_summaries": {
            i["probe_id"]: {
                "run_id": i["run_id"],
                "target_utc": i["target_utc"],
                "status": i["status"],
                "export_status": i["export_status"],
                "jsonext_roa_record_count": i["summary"].get("index_stats", {}).get("jsonext_roa_record_count"),
                "tuple_unique_count": i["summary"].get("index_stats", {}).get("tuple_unique_count"),
                "provenance_row_count": i["summary"].get("index_stats", {}).get("provenance_row_count"),
                "by_ta": i["summary"].get("index_stats", {}).get("by_ta"),
            }
            for i in probe_infos
        },
        "tuple_counts": {p: len(tuple_sets[p]) for p in probe_ids},
        "global_union_count": len(global_union),
        "global_intersection_count": len(global_intersection),
        "global_symmetric_region_count": len(diff_keys),
        "pairwise": pairwise,
        "affected_vrp_input_path": str(affected_path) if affected_path else None,
        "affected_vrp_input_count": len(affected),
        "affected_presence_distribution": dict(sorted(affected_presence_counter.items())),
        "affected_ta_count": dict(sorted(affected_ta_counter.items())),
        "affected_with_any_provenance": affected_with_any_provenance,
        "affected_all_probe_present": affected_all_probe_present,
        "affected_some_missing": affected_some_missing,
        "affected_absent_all": affected_absent_all,
        "outputs": {
            "tuple_presence_diff": str(diff_path),
            "selected_provenance_join": str(selected_join_path),
            "affected_vrp_provenance_mapping": str(affected_mapping_path),
        },
    }

    write_json(outputs_dir / "M21B_jsonext_collector_join_summary.json", summary)

    check_text = "\n".join([
        "M21B_JSONEXT_COLLECTOR_JOIN=PASS",
        "",
        f"archive_count = {len(archives)}",
        f"probe_ids = {probe_ids}",
        f"target_utc_values = {summary['target_utc_values']}",
        f"tuple_counts = {summary['tuple_counts']}",
        f"global_union_count = {len(global_union)}",
        f"global_intersection_count = {len(global_intersection)}",
        f"global_symmetric_region_count = {len(diff_keys)}",
        f"pairwise = {pairwise}",
        f"affected_vrp_input_count = {len(affected)}",
        f"affected_presence_distribution = {dict(sorted(affected_presence_counter.items()))}",
        f"affected_ta_count = {dict(sorted(affected_ta_counter.items()))}",
        f"affected_with_any_provenance = {affected_with_any_provenance}",
        f"affected_all_probe_present = {affected_all_probe_present}",
        f"affected_some_missing = {affected_some_missing}",
        f"affected_absent_all = {affected_absent_all}",
        f"summary_path = {outputs_dir / 'M21B_jsonext_collector_join_summary.json'}",
        f"affected_mapping_path = {affected_mapping_path}",
    ]) + "\n"

    (checks_dir / "M21B_jsonext_collector_join_check.txt").write_text(check_text, encoding="utf-8")
    print(check_text)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
