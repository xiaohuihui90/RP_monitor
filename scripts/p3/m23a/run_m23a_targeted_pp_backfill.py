#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_csv(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def run_cmd(cmd: list[str], timeout: int = 120) -> tuple[int, str, str, float]:
    start = time.time()
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="ignore",
            timeout=timeout,
        )
        return p.returncode, p.stdout, p.stderr, time.time() - start
    except subprocess.TimeoutExpired as e:
        return 124, e.stdout or "", e.stderr or "timeout", time.time() - start


def filename_from_uri(uri: str) -> str:
    return (uri or "").rstrip("/").rsplit("/", 1)[-1]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def stable_filelist_root(file_map: dict[str, str]) -> str:
    h = hashlib.sha256()
    for name in sorted(file_map):
        h.update(name.encode("utf-8"))
        h.update(b"\0")
        h.update(file_map[name].lower().encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


def fetch_rsync_file(uri: str, out_path: Path, timeout: int = 180) -> dict:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_dir = out_path.parent
    cmd = ["rsync", "-av", "--timeout=60", uri, str(tmp_dir) + "/"]
    rc, stdout, stderr, elapsed = run_cmd(cmd, timeout=timeout)
    fetched = tmp_dir / filename_from_uri(uri)
    ok = rc == 0 and fetched.exists()

    if ok and fetched != out_path:
        fetched.rename(out_path)

    return {
        "uri": uri,
        "out_path": str(out_path),
        "ok": ok,
        "returncode": rc,
        "elapsed_sec": round(elapsed, 4),
        "stdout_tail": stdout[-1000:],
        "stderr_tail": stderr[-1000:],
    }


def rsync_list(repo_base: str, timeout: int = 120) -> dict:
    cmd = ["rsync", "--list-only", "--timeout=60", repo_base]
    rc, stdout, stderr, elapsed = run_cmd(cmd, timeout=timeout)
    names = []
    if rc == 0:
        for line in stdout.splitlines():
            parts = line.split()
            if parts:
                names.append(parts[-1])
    return {
        "repo_base": repo_base,
        "ok": rc == 0,
        "returncode": rc,
        "elapsed_sec": round(elapsed, 4),
        "names": names,
        "stdout_tail": stdout[-2000:],
        "stderr_tail": stderr[-2000:],
    }


class DER:
    def __init__(self, data: bytes):
        self.data = data

    def read_tlv(self, pos: int):
        if pos >= len(self.data):
            raise ValueError("EOF")
        tag = self.data[pos]
        pos += 1
        if pos >= len(self.data):
            raise ValueError("EOF length")
        first = self.data[pos]
        pos += 1
        if first < 128:
            length = first
        else:
            n = first & 0x7F
            if n == 0 or n > 4:
                raise ValueError("unsupported length")
            length = int.from_bytes(self.data[pos:pos+n], "big")
            pos += n
        val = self.data[pos:pos+length]
        pos += length
        return tag, length, val, pos


def oid_to_str(v: bytes) -> str:
    if not v:
        return ""
    first = v[0]
    nums = [first // 40, first % 40]
    n = 0
    for b in v[1:]:
        n = (n << 7) | (b & 0x7F)
        if not (b & 0x80):
            nums.append(n)
            n = 0
    return ".".join(map(str, nums))


def parse_manifest_econtent(econtent: Path) -> dict:
    data = econtent.read_bytes()
    der = DER(data)
    tag, length, val, pos = der.read_tlv(0)
    if tag != 0x30:
        raise ValueError("Manifest eContent is not SEQUENCE")

    seq = DER(val)
    p = 0

    tag, length, v, p2 = seq.read_tlv(p)
    if tag == 0xA0:
        p = p2
        tag, length, v, p = seq.read_tlv(p)
    else:
        p = p2

    if tag != 0x02:
        raise ValueError("manifestNumber INTEGER not found")
    manifest_number = int.from_bytes(v, "big")

    tag, length, v, p = seq.read_tlv(p)
    if tag != 0x18:
        raise ValueError("thisUpdate GeneralizedTime not found")
    this_update = v.decode("ascii", errors="ignore")

    tag, length, v, p = seq.read_tlv(p)
    if tag != 0x18:
        raise ValueError("nextUpdate GeneralizedTime not found")
    next_update = v.decode("ascii", errors="ignore")

    tag, length, v, p = seq.read_tlv(p)
    if tag != 0x06:
        raise ValueError("fileHashAlg OID not found")
    file_hash_alg_oid = oid_to_str(v)

    tag, length, v, p = seq.read_tlv(p)
    if tag != 0x30:
        raise ValueError("fileList SEQUENCE not found")

    filelist_der = DER(v)
    q = 0
    files = {}
    while q < len(v):
        tag, length, item, q = filelist_der.read_tlv(q)
        if tag != 0x30:
            continue
        item_der = DER(item)
        ip = 0
        tag1, l1, file_v, ip = item_der.read_tlv(ip)
        tag2, l2, hash_v, ip = item_der.read_tlv(ip)
        if tag1 != 0x16 or tag2 != 0x03:
            continue
        name = file_v.decode("ascii", errors="ignore")
        hash_hex = hash_v[1:].hex() if hash_v else ""
        files[name] = hash_hex

    return {
        "manifestNumber": manifest_number,
        "thisUpdate": this_update,
        "nextUpdate": next_update,
        "fileHashAlgOid": file_hash_alg_oid,
        "fileList": files,
        "fileList_count": len(files),
        "fileList_root_sha256": stable_filelist_root(files),
    }


def extract_manifest_econtent(mft_path: Path, out_path: Path) -> dict:
    cmd = [
        "openssl", "cms", "-verify",
        "-inform", "DER",
        "-in", str(mft_path),
        "-noverify",
        "-no_attr_verify",
        "-no_content_verify",
        "-out", str(out_path),
    ]
    rc, stdout, stderr, elapsed = run_cmd(cmd, timeout=60)
    ok = rc == 0 and out_path.exists() and out_path.stat().st_size > 0
    return {
        "ok": ok,
        "returncode": rc,
        "elapsed_sec": round(elapsed, 4),
        "stdout_tail": stdout[-1000:],
        "stderr_tail": stderr[-1000:],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan-json", required=True)
    ap.add_argument("--candidate-seed-csv", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    plan_json = Path(args.plan_json)
    candidate_seed_csv = Path(args.candidate_seed_csv)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    plan = json.loads(plan_json.read_text(encoding="utf-8"))
    seeds = read_csv(candidate_seed_csv)
    capture_time = utc_now()

    object_root = out / "fetched_objects"
    object_root.mkdir(parents=True, exist_ok=True)

    by_target = defaultdict(list)
    for r in seeds:
        by_target[r["target_id"]].append(r)

    records = []
    repo_summaries = []
    feature_rows = []
    warnings = []

    for target in plan.get("targets", []):
        target_id = target["target_id"]
        repo_rank = target["repo_rank"]
        repo_base = target["repo_base"]
        repo_host = target["repo_host"]
        manifest_uri = target["manifest"]["manifest_uri"]
        manifest_filename = target["manifest"]["manifest_filename"]

        target_rows = by_target.get(target_id, [])
        target_dir = object_root / target_id
        target_dir.mkdir(parents=True, exist_ok=True)

        list_result = rsync_list(repo_base)
        if not list_result["ok"]:
            warnings.append(f"rsync_list_failed:{target_id}:{repo_base}")

        manifest_path = target_dir / manifest_filename
        manifest_fetch = fetch_rsync_file(manifest_uri, manifest_path, timeout=180)

        manifest_parse_status = "not_fetched"
        manifest_parsed = {}
        manifest_sha256 = ""

        if manifest_fetch["ok"]:
            manifest_sha256 = sha256_file(manifest_path)
            econtent_path = target_dir / (manifest_filename + ".econtent.der")
            extract = extract_manifest_econtent(manifest_path, econtent_path)
            if extract["ok"]:
                try:
                    manifest_parsed = parse_manifest_econtent(econtent_path)
                    manifest_parse_status = "parsed"
                except Exception as e:
                    manifest_parse_status = "parse_failed:" + str(e)
            else:
                manifest_parse_status = "openssl_failed"
        else:
            manifest_parse_status = "manifest_fetch_failed"

        filelist = manifest_parsed.get("fileList", {})

        target_roa_uris = sorted(set(r["roa_uri"] for r in target_rows if r.get("roa_uri")))
        roa_fetch_status = {}
        for roa_uri in target_roa_uris:
            roa_filename = filename_from_uri(roa_uri)
            roa_path = target_dir / roa_filename
            fetch = fetch_rsync_file(roa_uri, roa_path, timeout=120)
            sha = sha256_file(roa_path) if fetch["ok"] else ""
            roa_fetch_status[roa_uri] = {
                "roa_filename": roa_filename,
                "fetch_ok": fetch["ok"],
                "returncode": fetch["returncode"],
                "elapsed_sec": fetch["elapsed_sec"],
                "sha256": sha,
            }

        target_records = []
        for r in target_rows:
            roa_uri = r.get("roa_uri", "")
            roa_filename = filename_from_uri(roa_uri)
            expected_hash = filelist.get(roa_filename, "")
            fetched_sha = roa_fetch_status.get(roa_uri, {}).get("sha256", "")
            filelist_match = roa_filename in filelist
            hash_match = bool(expected_hash and fetched_sha and expected_hash.lower() == fetched_sha.lower())

            rec = dict(r)
            rec.update({
                "m23a_capture_time_utc": capture_time,
                "m23a_repo_rank": repo_rank,
                "m23a_target_id": target_id,
                "m23a_repo_host": repo_host,
                "m23a_repo_base": repo_base,
                "rsync_list_status": "success" if list_result["ok"] else "failed",
                "rsync_list_elapsed_sec": list_result["elapsed_sec"],
                "current_manifest_uri": manifest_uri,
                "current_manifest_filename": manifest_filename,
                "current_manifest_fetch_status": "success" if manifest_fetch["ok"] else "failed",
                "current_manifest_fetch_elapsed_sec": manifest_fetch["elapsed_sec"],
                "current_manifest_parse_status": manifest_parse_status,
                "current_manifest_sha256": manifest_sha256,
                "current_manifestNumber": manifest_parsed.get("manifestNumber", ""),
                "current_manifest_thisUpdate": manifest_parsed.get("thisUpdate", ""),
                "current_manifest_nextUpdate": manifest_parsed.get("nextUpdate", ""),
                "current_manifest_fileHashAlgOid": manifest_parsed.get("fileHashAlgOid", ""),
                "current_manifest_fileList_count": manifest_parsed.get("fileList_count", ""),
                "current_manifest_fileList_root_sha256": manifest_parsed.get("fileList_root_sha256", ""),
                "current_roa_fetch_status": "success" if roa_fetch_status.get(roa_uri, {}).get("fetch_ok") else "failed",
                "current_roa_sha256": fetched_sha,
                "current_manifest_filelist_match": filelist_match,
                "current_manifest_file_hash": expected_hash,
                "current_manifest_hash_match_fetched_roa": hash_match,
                "rrdp_available": False,
                "rrdp_reason": "not_in_m23a_batch2_rsync_backfill",
                "jsonext_available": False,
                "jsonext_reason": "not_collected_in_m23a_batch2",
                "validator_timing_available": False,
                "validator_timing_reason": "not_collected_in_m23a_batch2",
                "evidence_temporal_level": "L3_TARGETED_PP_BACKFILL",
                "semantic_boundary": "post_diff_targeted_pp_backfill_not_historical_causal_attribution",
            })
            records.append(rec)
            target_records.append(rec)

        total = len(target_records)
        filelist_match_count = sum(1 for r in target_records if r["current_manifest_filelist_match"] is True)
        hash_match_count = sum(1 for r in target_records if r["current_manifest_hash_match_fetched_roa"] is True)
        roa_fetch_success_count = sum(1 for x in roa_fetch_status.values() if x["fetch_ok"])

        repo_summary = {
            "target_id": target_id,
            "repo_rank": repo_rank,
            "repo_host": repo_host,
            "repo_base": repo_base,
            "candidate_count": total,
            "unique_roa_count": len(target_roa_uris),
            "unique_prefix_count": len(set(r.get("prefix", "") for r in target_records if r.get("prefix"))),
            "unique_asn_count": len(set(r.get("asn", "") for r in target_records if r.get("asn"))),
            "amplification_candidate_per_roa": round(total / len(target_roa_uris), 4) if target_roa_uris else 0,
            "rsync_list_status": "success" if list_result["ok"] else "failed",
            "current_manifest_uri": manifest_uri,
            "current_manifest_filename": manifest_filename,
            "current_manifest_fetch_status": "success" if manifest_fetch["ok"] else "failed",
            "current_manifest_parse_status": manifest_parse_status,
            "current_manifestNumber": manifest_parsed.get("manifestNumber", ""),
            "current_manifest_thisUpdate": manifest_parsed.get("thisUpdate", ""),
            "current_manifest_nextUpdate": manifest_parsed.get("nextUpdate", ""),
            "current_manifest_fileList_count": manifest_parsed.get("fileList_count", ""),
            "current_manifest_fileList_root_sha256": manifest_parsed.get("fileList_root_sha256", ""),
            "roa_fetch_success_count": roa_fetch_success_count,
            "filelist_match_count": filelist_match_count,
            "filelist_match_ratio": round(filelist_match_count / total, 4) if total else 0,
            "hash_match_count": hash_match_count,
            "hash_match_ratio": round(hash_match_count / total, 4) if total else 0,
            "is_post_diff_backfill": True,
            "is_same_window_capture": False,
            "semantic_boundary": "post_diff_targeted_pp_backfill_not_historical_causal_attribution",
        }
        repo_summaries.append(repo_summary)

        roa_c = Counter(r.get("roa_uri", "") for r in target_records if r.get("roa_uri"))
        fanout_roas = [roa for roa, cnt in roa_c.items() if cnt >= 10]

        feature_rows.append({
            "target_id": target_id,
            "repo_rank": repo_rank,
            "repo_host": repo_host,
            "repo_base": repo_base,
            "candidate_count": total,
            "unique_roa_count": len(target_roa_uris),
            "unique_prefix_count": repo_summary["unique_prefix_count"],
            "unique_asn_count": repo_summary["unique_asn_count"],
            "amplification_candidate_per_roa": repo_summary["amplification_candidate_per_roa"],
            "manifest_publication_cluster": repo_summary["filelist_match_ratio"] == 1.0 and repo_summary["hash_match_ratio"] == 1.0 and total >= 30,
            "roa_fanout_amplification": bool(fanout_roas),
            "fanout_roa_count": len(fanout_roas),
            "manifest_version_skew_candidate": "unknown_requires_same_window_or_longitudinal_backfill",
            "pp_fetch_reachability_candidate": "not_observed_if_all_fetch_success" if repo_summary["current_manifest_fetch_status"] == "success" and roa_fetch_success_count == len(target_roa_uris) else "possible_fetch_issue",
            "cache_trailing_candidate": "unknown_requires_validator_timing",
            "source_provenance_gap_candidate": "false_for_m22h_mapped_p0_targets",
            "requires_same_window_validation": True,
            "semantic_boundary": "root_cause_feature_seed_from_post_diff_backfill_not_final_root_cause",
        })

    record_fields = sorted(set(k for r in records for k in r.keys()))
    write_csv(out / "m23a_targeted_pp_backfill_records.csv", records, record_fields)

    with (out / "m23a_targeted_pp_backfill_records.jsonl").open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")

    repo_fields = [
        "target_id", "repo_rank", "repo_host", "repo_base",
        "candidate_count", "unique_roa_count", "unique_prefix_count", "unique_asn_count",
        "amplification_candidate_per_roa",
        "rsync_list_status",
        "current_manifest_uri", "current_manifest_filename",
        "current_manifest_fetch_status", "current_manifest_parse_status",
        "current_manifestNumber", "current_manifest_thisUpdate", "current_manifest_nextUpdate",
        "current_manifest_fileList_count", "current_manifest_fileList_root_sha256",
        "roa_fetch_success_count",
        "filelist_match_count", "filelist_match_ratio",
        "hash_match_count", "hash_match_ratio",
        "is_post_diff_backfill", "is_same_window_capture", "semantic_boundary",
    ]
    write_csv(out / "m23a_repo_level_summary.csv", repo_summaries, repo_fields)

    feature_fields = [
        "target_id", "repo_rank", "repo_host", "repo_base",
        "candidate_count", "unique_roa_count", "unique_prefix_count", "unique_asn_count",
        "amplification_candidate_per_roa",
        "manifest_publication_cluster",
        "roa_fanout_amplification",
        "fanout_roa_count",
        "manifest_version_skew_candidate",
        "pp_fetch_reachability_candidate",
        "cache_trailing_candidate",
        "source_provenance_gap_candidate",
        "requires_same_window_validation",
        "semantic_boundary",
    ]
    write_csv(out / "m23a_root_cause_feature_seed.csv", feature_rows, feature_fields)

    total_records = len(records)
    total_filelist_match = sum(1 for r in records if r.get("current_manifest_filelist_match") is True)
    total_hash_match = sum(1 for r in records if r.get("current_manifest_hash_match_fetched_roa") is True)
    fetch_failed = sum(1 for r in records if r.get("current_roa_fetch_status") != "success")

    summary = {
        "schema": "s3.m23a.targeted_pp_backfill.v1",
        "generated_at_utc": capture_time,
        "target_count": len(repo_summaries),
        "candidate_record_count": total_records,
        "filelist_match_count": total_filelist_match,
        "filelist_match_ratio": round(total_filelist_match / total_records, 4) if total_records else 0,
        "hash_match_count": total_hash_match,
        "hash_match_ratio": round(total_hash_match / total_records, 4) if total_records else 0,
        "fetch_failed_candidate_count": fetch_failed,
        "repo_summaries": repo_summaries,
        "warnings": warnings,
        "semantic_boundary": "post_diff_targeted_pp_backfill_not_historical_causal_attribution",
        "next_stage": "M23B_TARGETED_PP_LIVE_SAME_WINDOW_CAPTURE",
    }

    (out / "m23a_targeted_pp_backfill_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    md = []
    md.append("# M23A Targeted PP Backfill Summary")
    md.append("")
    md.append(f"- generated_at_utc: `{capture_time}`")
    md.append(f"- target_count: `{len(repo_summaries)}`")
    md.append(f"- candidate_record_count: `{total_records}`")
    md.append(f"- filelist_match_count: `{total_filelist_match}`")
    md.append(f"- filelist_match_ratio: `{summary['filelist_match_ratio']}`")
    md.append(f"- hash_match_count: `{total_hash_match}`")
    md.append(f"- hash_match_ratio: `{summary['hash_match_ratio']}`")
    md.append(f"- fetch_failed_candidate_count: `{fetch_failed}`")
    md.append(f"- semantic_boundary: `post_diff_targeted_pp_backfill_not_historical_causal_attribution`")
    md.append("")
    md.append("## Repo Summary")
    for r in repo_summaries:
        md.append(
            f"- {r['target_id']}: candidates=`{r['candidate_count']}`, unique_roa=`{r['unique_roa_count']}`, "
            f"manifest=`{r['current_manifest_filename']}`, manifestNumber=`{r['current_manifestNumber']}`, "
            f"fileList=`{r['current_manifest_fileList_count']}`, filelist_match_ratio=`{r['filelist_match_ratio']}`, "
            f"hash_match_ratio=`{r['hash_match_ratio']}`"
        )
    if warnings:
        md.append("")
        md.append("## Warnings")
        for w in warnings:
            md.append(f"- {w}")
    (out / "m23a_targeted_pp_backfill_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    status = "PASS" if total_records and repo_summaries else "FAIL"
    check = "\n".join([
        f"M23A_TARGETED_PP_BACKFILL={status}",
        f"generated_at_utc = {capture_time}",
        f"target_count = {len(repo_summaries)}",
        f"candidate_record_count = {total_records}",
        f"filelist_match_count = {total_filelist_match}",
        f"filelist_match_ratio = {summary['filelist_match_ratio']}",
        f"hash_match_count = {total_hash_match}",
        f"hash_match_ratio = {summary['hash_match_ratio']}",
        f"fetch_failed_candidate_count = {fetch_failed}",
        f"records_csv = {out / 'm23a_targeted_pp_backfill_records.csv'}",
        f"records_jsonl = {out / 'm23a_targeted_pp_backfill_records.jsonl'}",
        f"repo_summary_csv = {out / 'm23a_repo_level_summary.csv'}",
        f"root_cause_feature_seed_csv = {out / 'm23a_root_cause_feature_seed.csv'}",
        f"summary_json = {out / 'm23a_targeted_pp_backfill_summary.json'}",
        f"summary_md = {out / 'm23a_targeted_pp_backfill_summary.md'}",
        "semantic_boundary = post_diff_targeted_pp_backfill_not_historical_causal_attribution",
        "next_stage = M23B_TARGETED_PP_LIVE_SAME_WINDOW_CAPTURE",
        "",
    ])
    (out / "M23A_TARGETED_PP_BACKFILL_CHECK.txt").write_text(check, encoding="utf-8")
    print(check)


if __name__ == "__main__":
    main()
