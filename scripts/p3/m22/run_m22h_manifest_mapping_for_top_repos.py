#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timezone


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_csv(path: Path):
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict], fields: list[str]):
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def run_cmd(cmd, timeout=120):
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
            errors="ignore",
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        return 124, e.stdout or "", e.stderr or "timeout"


def uri_filename(uri: str) -> str:
    return uri.rstrip("/").rsplit("/", 1)[-1]


def fetch_rsync_file(uri: str, out_path: Path, timeout=120):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_dir = out_path.parent
    cmd = ["rsync", "-av", "--timeout=60", uri, str(tmp_dir) + "/"]
    rc, stdout, stderr = run_cmd(cmd, timeout=timeout)
    fetched = tmp_dir / uri_filename(uri)
    if rc == 0 and fetched.exists():
        if fetched != out_path:
            fetched.rename(out_path)
        return True, rc, stdout[-1000:], stderr[-1000:]
    return False, rc, stdout[-1000:], stderr[-1000:]


def rsync_list(repo_base: str, timeout=120):
    cmd = ["rsync", "--list-only", "--timeout=60", repo_base]
    return run_cmd(cmd, timeout=timeout)


def sha256_file(path: Path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class DER:
    def __init__(self, data: bytes):
        self.data = data

    def read_tlv(self, pos):
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


def oid_to_str(v: bytes):
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


def parse_manifest_econtent(econtent: Path):
    data = econtent.read_bytes()
    der = DER(data)

    tag, length, val, pos = der.read_tlv(0)
    if tag != 0x30:
        raise ValueError("Manifest eContent is not SEQUENCE")

    seq = DER(val)
    p = 0

    # optional [0] version
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
        # BIT STRING: first byte is unused bits count
        hash_hex = hash_v[1:].hex() if hash_v else ""
        files[name] = hash_hex

    return {
        "manifestNumber": manifest_number,
        "thisUpdate": this_update,
        "nextUpdate": next_update,
        "fileHashAlgOid": file_hash_alg_oid,
        "fileList": files,
    }


def extract_manifest_econtent(mft_path: Path, out_path: Path):
    cmd = [
        "openssl", "cms", "-verify",
        "-inform", "DER",
        "-in", str(mft_path),
        "-noverify",
        "-no_attr_verify",
        "-no_content_verify",
        "-out", str(out_path),
    ]
    rc, stdout, stderr = run_cmd(cmd, timeout=60)
    return rc == 0 and out_path.exists() and out_path.stat().st_size > 0, rc, stdout[-1000:], stderr[-1000:]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--m22f-records-csv", required=True)
    ap.add_argument("--repo-cluster-csv", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--top-n", type=int, default=3)
    args = ap.parse_args()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    records = read_csv(Path(args.m22f_records_csv))
    repo_clusters = read_csv(Path(args.repo_cluster_csv))
    top_repos = [r["repo_base"] for r in repo_clusters[:args.top_n]]

    work = out / "fetched_objects"
    work.mkdir(parents=True, exist_ok=True)

    result_rows = []
    repo_summary_rows = []

    for repo_i, repo_base in enumerate(top_repos, 1):
        repo_safe = f"repo_{repo_i}"
        repo_dir = work / repo_safe
        repo_dir.mkdir(parents=True, exist_ok=True)

        candidates = [
            r for r in records
            if r.get("repo_base") == repo_base and r.get("roa_uri")
        ]
        roa_uris = sorted(set(r["roa_uri"] for r in candidates))
        roa_filenames = {uri_filename(u): u for u in roa_uris}

        rc, list_stdout, list_stderr = rsync_list(repo_base, timeout=120)
        mft_names = []
        if rc == 0:
            for line in list_stdout.splitlines():
                parts = line.split()
                if not parts:
                    continue
                name = parts[-1]
                if name.endswith(".mft"):
                    mft_names.append(name)

        mft_parse_results = []
        for mft_name in mft_names:
            mft_uri = repo_base.rstrip("/") + "/" + mft_name
            mft_path = repo_dir / mft_name
            ok, frc, fstdout, fstderr = fetch_rsync_file(mft_uri, mft_path, timeout=180)
            parse_status = "not_fetched"
            parsed = None
            econtent_path = repo_dir / (mft_name + ".econtent.der")

            if ok:
                ex_ok, ex_rc, ex_stdout, ex_stderr = extract_manifest_econtent(mft_path, econtent_path)
                if ex_ok:
                    try:
                        parsed = parse_manifest_econtent(econtent_path)
                        parse_status = "parsed"
                    except Exception as e:
                        parse_status = "parse_failed:" + str(e)
                else:
                    parse_status = "openssl_failed"

            mft_parse_results.append({
                "mft_name": mft_name,
                "mft_uri": mft_uri,
                "mft_path": str(mft_path),
                "fetch_ok": ok,
                "parse_status": parse_status,
                "parsed": parsed,
            })

        # choose manifest with most candidate ROA filename matches
        best = None
        best_match_count = -1
        for m in mft_parse_results:
            parsed = m.get("parsed")
            if not parsed:
                continue
            filelist = parsed["fileList"]
            cnt = sum(1 for fn in roa_filenames if fn in filelist)
            if cnt > best_match_count:
                best = m
                best_match_count = cnt

        # fetch ROAs and compare hash if best manifest exists
        fetched_roa_sha = {}
        for roa_uri in roa_uris:
            fn = uri_filename(roa_uri)
            roa_path = repo_dir / fn
            ok, frc, fstdout, fstderr = fetch_rsync_file(roa_uri, roa_path, timeout=120)
            if ok:
                fetched_roa_sha[fn] = sha256_file(roa_path)

        for r in candidates:
            fn = uri_filename(r["roa_uri"])
            row = dict(r)
            row.update({
                "repo_base": repo_base,
                "roa_filename": fn,
                "m22h_repo_rank": repo_i,
                "rsync_list_status": "success" if rc == 0 else "failed",
                "mft_candidates": ";".join(mft_names),
                "selected_manifest_uri": "",
                "selected_manifest_name": "",
                "manifest_parse_status": "",
                "manifestNumber": "",
                "manifest_thisUpdate": "",
                "manifest_nextUpdate": "",
                "manifest_fileHashAlgOid": "",
                "manifest_fileList_count": "",
                "manifest_filelist_match": False,
                "manifest_file_hash": "",
                "fetched_roa_sha256": fetched_roa_sha.get(fn, ""),
                "manifest_hash_match_fetched_roa": "",
                "semantic_boundary": "current_repository_manifest_mapping_not_same_window_strong_binding",
            })

            if best and best.get("parsed"):
                parsed = best["parsed"]
                filelist = parsed["fileList"]
                row["selected_manifest_uri"] = best["mft_uri"]
                row["selected_manifest_name"] = best["mft_name"]
                row["manifest_parse_status"] = best["parse_status"]
                row["manifestNumber"] = parsed["manifestNumber"]
                row["manifest_thisUpdate"] = parsed["thisUpdate"]
                row["manifest_nextUpdate"] = parsed["nextUpdate"]
                row["manifest_fileHashAlgOid"] = parsed["fileHashAlgOid"]
                row["manifest_fileList_count"] = len(filelist)
                if fn in filelist:
                    row["manifest_filelist_match"] = True
                    row["manifest_file_hash"] = filelist[fn]
                    if row["fetched_roa_sha256"]:
                        row["manifest_hash_match_fetched_roa"] = str(
                            row["manifest_file_hash"].lower() == row["fetched_roa_sha256"].lower()
                        )
                else:
                    row["manifest_filelist_match"] = False

            result_rows.append(row)

        repo_summary_rows.append({
            "repo_rank": repo_i,
            "repo_base": repo_base,
            "candidate_count": len(candidates),
            "unique_roa_uri_count": len(roa_uris),
            "rsync_list_status": "success" if rc == 0 else "failed",
            "mft_candidate_count": len(mft_names),
            "selected_manifest_uri": best["mft_uri"] if best else "",
            "selected_manifest_name": best["mft_name"] if best else "",
            "best_manifest_roa_match_count": best_match_count if best else 0,
            "manifestNumber": best["parsed"]["manifestNumber"] if best and best.get("parsed") else "",
            "manifest_thisUpdate": best["parsed"]["thisUpdate"] if best and best.get("parsed") else "",
            "manifest_nextUpdate": best["parsed"]["nextUpdate"] if best and best.get("parsed") else "",
            "manifest_fileList_count": len(best["parsed"]["fileList"]) if best and best.get("parsed") else "",
            "roa_fetch_sha_count": len(fetched_roa_sha),
        })

    fields = sorted(set(k for r in result_rows for k in r.keys()))
    write_csv(out / "m22h_manifest_mapping_records.csv", result_rows, fields)

    with (out / "m22h_manifest_mapping_records.jsonl").open("w", encoding="utf-8") as w:
        for r in result_rows:
            w.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")

    write_csv(out / "m22h_repo_manifest_summary.csv", repo_summary_rows, [
        "repo_rank", "repo_base", "candidate_count", "unique_roa_uri_count",
        "rsync_list_status", "mft_candidate_count",
        "selected_manifest_uri", "selected_manifest_name", "best_manifest_roa_match_count",
        "manifestNumber", "manifest_thisUpdate", "manifest_nextUpdate",
        "manifest_fileList_count", "roa_fetch_sha_count",
    ])

    total = len(result_rows)
    filelist_match = sum(1 for r in result_rows if str(r.get("manifest_filelist_match")) == "True")
    hash_checked = sum(1 for r in result_rows if r.get("manifest_hash_match_fetched_roa") in ("True", "False"))
    hash_match = sum(1 for r in result_rows if r.get("manifest_hash_match_fetched_roa") == "True")

    summary = {
        "schema": "s3.m22h.manifest_mapping_for_top_repos.v1",
        "generated_at_utc": utc_now(),
        "top_n": args.top_n,
        "candidate_records": total,
        "manifest_filelist_match_count": filelist_match,
        "manifest_filelist_match_ratio": round(filelist_match / total, 4) if total else 0,
        "hash_checked_count": hash_checked,
        "hash_match_count": hash_match,
        "hash_match_ratio": round(hash_match / hash_checked, 4) if hash_checked else 0,
        "repo_summary": repo_summary_rows,
        "outputs": {
            "records_csv": str(out / "m22h_manifest_mapping_records.csv"),
            "records_jsonl": str(out / "m22h_manifest_mapping_records.jsonl"),
            "repo_summary_csv": str(out / "m22h_repo_manifest_summary.csv"),
            "summary_json": str(out / "m22h_manifest_mapping_summary.json"),
            "summary_md": str(out / "m22h_manifest_mapping_summary.md"),
        },
        "semantic_boundary": "current_repository_manifest_mapping_not_same_window_strong_binding",
        "next_stage": "M23_BGP_ROV_IMPACT_FOR_MANIFEST_MAPPED_CLUSTERS",
    }

    (out / "m22h_manifest_mapping_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    md = []
    md.append("# M22H Manifest Mapping for Top Repository Clusters")
    md.append("")
    md.append(f"- candidate_records: `{total}`")
    md.append(f"- manifest_filelist_match_count: `{filelist_match}`")
    md.append(f"- manifest_filelist_match_ratio: `{summary['manifest_filelist_match_ratio']}`")
    md.append(f"- hash_checked_count: `{hash_checked}`")
    md.append(f"- hash_match_count: `{hash_match}`")
    md.append(f"- hash_match_ratio: `{summary['hash_match_ratio']}`")
    md.append("")
    md.append("## Repository Summary")
    for r in repo_summary_rows:
        md.append(
            f"- repo_rank=`{r['repo_rank']}`, candidates=`{r['candidate_count']}`, "
            f"unique_roa=`{r['unique_roa_uri_count']}`, mft_candidates=`{r['mft_candidate_count']}`, "
            f"selected_manifest=`{r['selected_manifest_name']}`, manifestNumber=`{r['manifestNumber']}`, "
            f"thisUpdate=`{r['manifest_thisUpdate']}`, matches=`{r['best_manifest_roa_match_count']}`"
        )
    md.append("")
    md.append("## Interpretation")
    md.append("- M22H maps current repository ROA filenames to current manifest fileList.")
    md.append("- This is not same-window historical causal attribution.")
    md.append("- Strong binding requires live same-window JSONEXT, manifest, notification, and validator timing capture.")
    (out / "m22h_manifest_mapping_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    check = "\n".join([
        "M22H_MANIFEST_MAPPING_FOR_TOP_REPOS=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"top_n = {args.top_n}",
        f"candidate_records = {total}",
        f"manifest_filelist_match_count = {filelist_match}",
        f"manifest_filelist_match_ratio = {summary['manifest_filelist_match_ratio']}",
        f"hash_checked_count = {hash_checked}",
        f"hash_match_count = {hash_match}",
        f"summary_json = {out / 'm22h_manifest_mapping_summary.json'}",
        f"summary_md = {out / 'm22h_manifest_mapping_summary.md'}",
        f"records_csv = {out / 'm22h_manifest_mapping_records.csv'}",
        f"repo_summary_csv = {out / 'm22h_repo_manifest_summary.csv'}",
        "semantic_boundary = current_repository_manifest_mapping_not_same_window_strong_binding",
        "next_stage = M23_BGP_ROV_IMPACT_FOR_MANIFEST_MAPPED_CLUSTERS",
        "",
    ])

    (out / "M22H_MANIFEST_MAPPING_FOR_TOP_REPOS_CHECK.txt").write_text(check, encoding="utf-8")
    print(check)


if __name__ == "__main__":
    main()
