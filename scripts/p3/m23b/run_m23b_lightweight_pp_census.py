#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import time
from collections import Counter
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


def stable_filelist_root(files: dict[str, str]) -> str:
    h = hashlib.sha256()
    for name in sorted(files):
        h.update(name.encode("utf-8"))
        h.update(b"\0")
        h.update(files[name].lower().encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


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
        "ok": rc == 0,
        "returncode": rc,
        "elapsed_sec": round(elapsed, 4),
        "names": names,
        "stderr_tail": stderr[-1000:],
    }


def fetch_rsync_file(uri: str, out_path: Path, timeout: int = 180) -> dict:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["rsync", "-av", "--timeout=60", uri, str(out_path.parent) + "/"]
    rc, stdout, stderr, elapsed = run_cmd(cmd, timeout=timeout)
    fetched = out_path.parent / filename_from_uri(uri)
    ok = rc == 0 and fetched.exists()
    if ok and fetched != out_path:
        fetched.rename(out_path)
    return {
        "ok": ok,
        "returncode": rc,
        "elapsed_sec": round(elapsed, 4),
        "stderr_tail": stderr[-1000:],
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
        "stderr_tail": stderr[-1000:],
    }


def parse_manifest_econtent(path: Path) -> dict:
    data = path.read_bytes()
    der = DER(data)
    tag, length, val, pos = der.read_tlv(0)
    if tag != 0x30:
        raise ValueError("eContent is not SEQUENCE")

    seq = DER(val)
    p = 0

    tag, length, v, p2 = seq.read_tlv(p)
    if tag == 0xA0:
        p = p2
        tag, length, v, p = seq.read_tlv(p)
    else:
        p = p2

    if tag != 0x02:
        raise ValueError("manifestNumber not found")
    manifest_number = int.from_bytes(v, "big")

    tag, length, v, p = seq.read_tlv(p)
    if tag != 0x18:
        raise ValueError("thisUpdate not found")
    this_update = v.decode("ascii", errors="ignore")

    tag, length, v, p = seq.read_tlv(p)
    if tag != 0x18:
        raise ValueError("nextUpdate not found")
    next_update = v.decode("ascii", errors="ignore")

    tag, length, v, p = seq.read_tlv(p)
    if tag != 0x06:
        raise ValueError("fileHashAlg not found")
    alg = oid_to_str(v)

    tag, length, v, p = seq.read_tlv(p)
    if tag != 0x30:
        raise ValueError("fileList not found")

    files = {}
    fl = DER(v)
    q = 0
    while q < len(v):
        tag, length, item, q = fl.read_tlv(q)
        if tag != 0x30:
            continue
        d = DER(item)
        ip = 0
        tag1, l1, name_v, ip = d.read_tlv(ip)
        tag2, l2, hash_v, ip = d.read_tlv(ip)
        if tag1 == 0x16 and tag2 == 0x03:
            name = name_v.decode("ascii", errors="ignore")
            files[name] = hash_v[1:].hex() if hash_v else ""

    return {
        "manifestNumber": manifest_number,
        "thisUpdate": this_update,
        "nextUpdate": next_update,
        "fileHashAlgOid": alg,
        "fileList_count": len(files),
        "fileList_root_sha256": stable_filelist_root(files),
    }


def classify_failure(stderr: str) -> tuple[bool, bool, str]:
    s = stderr or ""
    connection_limit = "max connections" in s
    timeout_error = "timeout" in s.lower() or "timed out" in s.lower()
    if connection_limit:
        failure_type = "server_side_max_connections"
    elif timeout_error:
        failure_type = "timeout"
    elif s:
        failure_type = "rsync_error"
    else:
        failure_type = ""
    return connection_limit, timeout_error, failure_type


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target-set-csv", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--max-targets", type=int, default=0, help="0 means all")
    args = ap.parse_args()

    target_csv = Path(args.target_set_csv)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    targets = read_csv(target_csv)
    if args.max_targets and args.max_targets > 0:
        targets = targets[: args.max_targets]

    capture_time = utc_now()
    obj_root = out / "m23b_lightweight_objects"
    obj_root.mkdir(parents=True, exist_ok=True)

    rows = []
    for idx, t in enumerate(targets, 1):
        repo_base = t.get("repo_base", "")
        target_id = t.get("target_id", f"target_{idx}")
        target_dir = obj_root / target_id
        target_dir.mkdir(parents=True, exist_ok=True)

        base = {
            "capture_time_utc": capture_time,
            "target_id": target_id,
            "target_priority": t.get("target_priority", ""),
            "capture_mode": t.get("capture_mode", ""),
            "capture_reason": t.get("capture_reason", ""),
            "tal": t.get("tal_top", ""),
            "repo_host": t.get("repo_host", ""),
            "repo_base": repo_base,
            "candidate_count": t.get("candidate_count", ""),
            "unique_roa_count": t.get("unique_roa_count", ""),
            "unique_prefix_count": t.get("unique_prefix_count", ""),
            "unique_asn_count": t.get("unique_asn_count", ""),
            "amplification_candidate_per_roa": t.get("amplification_candidate_per_roa", ""),
            "source_bridge_status": t.get("source_bridge_status", ""),
            "input_evidence_level": t.get("evidence_level", ""),
        }

        if not repo_base:
            row = dict(base)
            row.update({
                "rsync_reachable": False,
                "rsync_list_status": "not_applicable_no_repo_base",
                "fetch_failure_type": "source_provenance_gap_no_repo_base",
                "connection_limit_error": False,
                "timeout_error": False,
                "manifest_uri": "",
                "manifest_fetch_status": "not_attempted",
                "manifest_parse_status": "not_attempted",
                "manifestNumber": "",
                "manifest_thisUpdate": "",
                "manifest_nextUpdate": "",
                "manifest_fileList_count": "",
                "manifest_fileList_root_sha256": "",
                "evidence_level": "E0_VRP_ONLY",
                "semantic_boundary": "m23b_lightweight_census_source_provenance_gap_no_live_pp_fetch",
            })
            rows.append(row)
            continue

        list_result = rsync_list(repo_base)
        conn_limit, timeout_err, failure_type = classify_failure(list_result["stderr_tail"])

        mft_names = [n for n in list_result["names"] if n.endswith(".mft")]
        selected_mft = mft_names[0] if mft_names else ""
        manifest_uri = repo_base.rstrip("/") + "/" + selected_mft if selected_mft else ""

        manifest_fetch_status = "not_attempted"
        manifest_parse_status = "not_attempted"
        manifest_sha256 = ""
        manifest_parsed = {}

        if manifest_uri:
            mft_path = target_dir / selected_mft
            fetch = fetch_rsync_file(manifest_uri, mft_path)
            manifest_fetch_status = "success" if fetch["ok"] else "failed"
            if not fetch["ok"]:
                f_conn, f_timeout, f_type = classify_failure(fetch["stderr_tail"])
                conn_limit = conn_limit or f_conn
                timeout_err = timeout_err or f_timeout
                failure_type = f_type or failure_type
            else:
                manifest_sha256 = sha256_file(mft_path)
                econtent = target_dir / (selected_mft + ".econtent.der")
                ext = extract_manifest_econtent(mft_path, econtent)
                if ext["ok"]:
                    try:
                        manifest_parsed = parse_manifest_econtent(econtent)
                        manifest_parse_status = "parsed"
                    except Exception as e:
                        manifest_parse_status = "parse_failed:" + str(e)
                else:
                    manifest_parse_status = "openssl_failed"

        row = dict(base)
        row.update({
            "rsync_reachable": list_result["ok"],
            "rsync_list_status": "success" if list_result["ok"] else "failed",
            "rsync_list_elapsed_sec": list_result["elapsed_sec"],
            "fetch_failure_type": failure_type,
            "connection_limit_error": conn_limit,
            "timeout_error": timeout_err,
            "mft_candidate_count": len(mft_names),
            "manifest_uri": manifest_uri,
            "manifest_filename": selected_mft,
            "manifest_fetch_status": manifest_fetch_status,
            "manifest_parse_status": manifest_parse_status,
            "manifest_sha256": manifest_sha256,
            "manifestNumber": manifest_parsed.get("manifestNumber", ""),
            "manifest_thisUpdate": manifest_parsed.get("thisUpdate", ""),
            "manifest_nextUpdate": manifest_parsed.get("nextUpdate", ""),
            "manifest_fileHashAlgOid": manifest_parsed.get("fileHashAlgOid", ""),
            "manifest_fileList_count": manifest_parsed.get("fileList_count", ""),
            "manifest_fileList_root_sha256": manifest_parsed.get("fileList_root_sha256", ""),
            "rrdp_notification_uri": "",
            "notification_fetch_status": "not_attempted_no_rrdp_uri",
            "notification_session_id": "",
            "notification_serial": "",
            "notification_digest": "",
            "jsonext_available": False,
            "validator_timing_available": False,
            "evidence_level": "E3_LIVE_PP_CENSUS" if manifest_parse_status == "parsed" else "E1_SOURCE_BRIDGE",
            "semantic_boundary": "m23b_lightweight_pp_census_single_probe_not_same_window_multi_probe_attribution",
        })
        rows.append(row)

    fields = sorted(set(k for r in rows for k in r.keys()))
    write_csv(out / "m23b_lightweight_pp_census_records.csv", rows, fields)

    with (out / "m23b_lightweight_pp_census_records.jsonl").open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")

    by_priority = Counter(r.get("target_priority", "") for r in rows)
    by_tal = Counter(r.get("tal", "") for r in rows)
    by_fetch = Counter(r.get("fetch_failure_type", "") or "success_or_not_attempted" for r in rows)

    summary = {
        "schema": "s3.m23b.lightweight_pp_census.v1",
        "generated_at_utc": capture_time,
        "target_count": len(rows),
        "rsync_success_count": sum(1 for r in rows if r.get("rsync_list_status") == "success"),
        "manifest_parsed_count": sum(1 for r in rows if r.get("manifest_parse_status") == "parsed"),
        "connection_limit_error_count": sum(1 for r in rows if str(r.get("connection_limit_error")) == "True"),
        "timeout_error_count": sum(1 for r in rows if str(r.get("timeout_error")) == "True"),
        "by_priority": dict(by_priority),
        "by_tal": dict(by_tal),
        "by_fetch_failure_type": dict(by_fetch),
        "semantic_boundary": "m23b_lightweight_pp_census_single_probe_not_same_window_multi_probe_attribution",
    }

    (out / "m23b_lightweight_pp_census_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    md = []
    md.append("# M23B Lightweight PP Census Summary")
    md.append("")
    md.append(f"- generated_at_utc: `{capture_time}`")
    md.append(f"- target_count: `{summary['target_count']}`")
    md.append(f"- rsync_success_count: `{summary['rsync_success_count']}`")
    md.append(f"- manifest_parsed_count: `{summary['manifest_parsed_count']}`")
    md.append(f"- connection_limit_error_count: `{summary['connection_limit_error_count']}`")
    md.append(f"- timeout_error_count: `{summary['timeout_error_count']}`")
    md.append(f"- by_priority: `{summary['by_priority']}`")
    md.append(f"- by_tal: `{summary['by_tal']}`")
    md.append(f"- by_fetch_failure_type: `{summary['by_fetch_failure_type']}`")
    md.append("")
    md.append("Semantic boundary: single-probe lightweight census, not multi-probe same-window attribution.")
    (out / "m23b_lightweight_pp_census_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    check = "\n".join([
        "M23B_C_LIGHTWEIGHT_PP_CENSUS=PASS" if rows else "M23B_C_LIGHTWEIGHT_PP_CENSUS=FAIL",
        f"generated_at_utc = {capture_time}",
        f"target_count = {summary['target_count']}",
        f"rsync_success_count = {summary['rsync_success_count']}",
        f"manifest_parsed_count = {summary['manifest_parsed_count']}",
        f"connection_limit_error_count = {summary['connection_limit_error_count']}",
        f"timeout_error_count = {summary['timeout_error_count']}",
        f"records_csv = {out / 'm23b_lightweight_pp_census_records.csv'}",
        f"records_jsonl = {out / 'm23b_lightweight_pp_census_records.jsonl'}",
        f"summary_json = {out / 'm23b_lightweight_pp_census_summary.json'}",
        f"summary_md = {out / 'm23b_lightweight_pp_census_summary.md'}",
        "semantic_boundary = m23b_lightweight_pp_census_single_probe_not_same_window_multi_probe_attribution",
        "next_stage = M23B_D_HIGH_IMPACT_SAME_WINDOW_CAPTURE",
        "",
    ])
    (out / "M23B_C_LIGHTWEIGHT_CENSUS_CHECK.txt").write_text(check, encoding="utf-8")
    print(check)


if __name__ == "__main__":
    main()
