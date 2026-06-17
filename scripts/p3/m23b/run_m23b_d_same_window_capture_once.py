#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_csv(path: Path):
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows, fields):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def run_cmd(cmd, timeout=120):
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
        return p.returncode, p.stdout, p.stderr, round(time.time() - start, 4)
    except subprocess.TimeoutExpired as e:
        return 124, e.stdout or "", e.stderr or "timeout", round(time.time() - start, 4)


def filename_from_uri(uri: str):
    return (uri or "").rstrip("/").rsplit("/", 1)[-1]


def sha256_file(path: Path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def failure_type(stderr: str):
    s = stderr or ""
    low = s.lower()
    if "max connections" in s:
        return "server_side_max_connections"
    if "timeout" in low or "timed out" in low:
        return "timeout"
    if s.strip():
        return "rsync_error"
    return ""


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


def filelist_root(files):
    h = hashlib.sha256()
    for k in sorted(files):
        h.update(k.encode("utf-8"))
        h.update(b"\0")
        h.update(files[k].lower().encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


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
    rc, stdout, stderr, elapsed = run_cmd(cmd, timeout=60)
    ok = rc == 0 and out_path.exists() and out_path.stat().st_size > 0
    return ok, rc, stderr, elapsed


def parse_manifest_econtent(path: Path):
    data = path.read_bytes()
    der = DER(data)
    tag, length, val, pos = der.read_tlv(0)
    if tag != 0x30:
        raise ValueError("not sequence")

    seq = DER(val)
    p = 0

    tag, length, v, p2 = seq.read_tlv(p)
    if tag == 0xA0:
        p = p2
        tag, length, v, p = seq.read_tlv(p)
    else:
        p = p2

    if tag != 0x02:
        raise ValueError("manifestNumber missing")
    manifest_number = int.from_bytes(v, "big")

    tag, length, v, p = seq.read_tlv(p)
    if tag != 0x18:
        raise ValueError("thisUpdate missing")
    this_update = v.decode("ascii", errors="ignore")

    tag, length, v, p = seq.read_tlv(p)
    if tag != 0x18:
        raise ValueError("nextUpdate missing")
    next_update = v.decode("ascii", errors="ignore")

    tag, length, v, p = seq.read_tlv(p)
    if tag != 0x06:
        raise ValueError("fileHashAlg missing")
    alg = oid_to_str(v)

    tag, length, v, p = seq.read_tlv(p)
    if tag != 0x30:
        raise ValueError("fileList missing")

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
        "fileList_root_sha256": filelist_root(files),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target-list-csv", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--capture-id", default="")
    args = ap.parse_args()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    capture_time = utc_now()
    capture_id = args.capture_id or "m23b_d_capture_" + capture_time.replace("-", "").replace(":", "")
    capture_dir = out / "captures" / capture_id
    capture_dir.mkdir(parents=True, exist_ok=True)

    targets = read_csv(Path(args.target_list_csv))
    records = []

    for t in targets:
        target_id = t["target_id"]
        repo_base = t["repo_base"]
        target_dir = capture_dir / target_id
        target_dir.mkdir(parents=True, exist_ok=True)

        # L2 / reachability: rsync list
        rc, stdout, stderr, elapsed = run_cmd(
            ["rsync", "--list-only", "--timeout=60", repo_base],
            timeout=120,
        )
        list_ok = rc == 0
        ftype = failure_type(stderr)

        mft_names = []
        if list_ok:
            for line in stdout.splitlines():
                parts = line.split()
                if parts:
                    name = parts[-1]
                    if name.endswith(".mft"):
                        mft_names.append(name)

        selected_mft = mft_names[0] if mft_names else ""
        manifest_uri = repo_base.rstrip("/") + "/" + selected_mft if selected_mft else ""

        manifest_fetch_status = "not_attempted"
        manifest_parse_status = "not_attempted"
        manifest_sha256 = ""
        parsed = {}

        if manifest_uri:
            mft_path = target_dir / selected_mft
            rc2, stdout2, stderr2, elapsed2 = run_cmd(
                ["rsync", "-av", "--timeout=60", manifest_uri, str(target_dir) + "/"],
                timeout=180,
            )
            fetched = target_dir / selected_mft
            fetch_ok = rc2 == 0 and fetched.exists()
            manifest_fetch_status = "success" if fetch_ok else "failed"
            if not fetch_ok:
                ftype = failure_type(stderr2) or ftype
            else:
                manifest_sha256 = sha256_file(fetched)
                econtent = target_dir / (selected_mft + ".econtent.der")
                ok, rc3, stderr3, elapsed3 = extract_manifest_econtent(fetched, econtent)
                if ok:
                    try:
                        parsed = parse_manifest_econtent(econtent)
                        manifest_parse_status = "parsed"
                    except Exception as e:
                        manifest_parse_status = "parse_failed:" + str(e)
                else:
                    manifest_parse_status = "openssl_failed"

        records.append({
            "capture_id": capture_id,
            "capture_time_utc": capture_time,
            "target_id": target_id,
            "target_priority": t.get("target_priority", ""),
            "tal": t.get("tal", ""),
            "repo_host": t.get("repo_host", ""),
            "repo_base": repo_base,
            "candidate_count": t.get("candidate_count", ""),
            "unique_roa_count": t.get("unique_roa_count", ""),
            "unique_prefix_count": t.get("unique_prefix_count", ""),
            "amplification_candidate_per_roa": t.get("amplification_candidate_per_roa", ""),
            "capture_reason": t.get("capture_reason", ""),
            "rsync_list_status": "success" if list_ok else "failed",
            "rsync_list_returncode": rc,
            "rsync_list_elapsed_sec": elapsed,
            "fetch_failure_type": ftype,
            "connection_limit_error": "max_connections" in ftype,
            "timeout_error": ftype == "timeout",
            "mft_candidate_count": len(mft_names),
            "manifest_uri": manifest_uri,
            "manifest_filename": selected_mft,
            "manifest_fetch_status": manifest_fetch_status,
            "manifest_parse_status": manifest_parse_status,
            "manifest_sha256": manifest_sha256,
            "manifestNumber": parsed.get("manifestNumber", ""),
            "manifest_thisUpdate": parsed.get("thisUpdate", ""),
            "manifest_nextUpdate": parsed.get("nextUpdate", ""),
            "manifest_fileHashAlgOid": parsed.get("fileHashAlgOid", ""),
            "manifest_fileList_count": parsed.get("fileList_count", ""),
            "manifest_fileList_root_sha256": parsed.get("fileList_root_sha256", ""),
            "l1_notification_status": "not_collected_no_rrdp_uri_mapping_yet",
            "l1_session_id": "",
            "l1_serial": "",
            "l1_notification_digest": "",
            "l3_jsonext_status": "not_collected_in_this_single_node_capture",
            "validator_timing_status": "not_collected_in_this_single_node_capture",
            "evidence_level": "E3_LIVE_PP_CENSUS" if manifest_parse_status == "parsed" else "E1_SOURCE_BRIDGE_OR_FETCH_FAILURE",
            "semantic_boundary": "single_node_live_capture_not_multi_probe_same_window_attribution",
        })

    fields = sorted(set(k for r in records for k in r.keys()))
    records_csv = out / "m23b_d_same_window_capture_records.csv"
    existing = []
    if records_csv.exists():
        existing = read_csv(records_csv)
    all_records = existing + records
    write_csv(records_csv, all_records, fields)

    with (out / "m23b_d_same_window_capture_records.jsonl").open("a", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")

    success = sum(1 for r in records if r["manifest_parse_status"] == "parsed")
    conn = sum(1 for r in records if r["connection_limit_error"])
    fail = sum(1 for r in records if r["rsync_list_status"] != "success")

    summary = {
        "schema": "s3.m23b.d.same_window_capture_once.v1",
        "capture_id": capture_id,
        "capture_time_utc": capture_time,
        "target_count": len(records),
        "manifest_parsed_count": success,
        "rsync_failed_count": fail,
        "connection_limit_error_count": conn,
        "semantic_boundary": "single_node_live_capture_not_multi_probe_same_window_attribution",
    }

    (out / f"{capture_id}_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    md = []
    md.append("# M23B-D Same-window Capture Once Summary")
    md.append("")
    md.append(f"- capture_id: `{capture_id}`")
    md.append(f"- capture_time_utc: `{capture_time}`")
    md.append(f"- target_count: `{len(records)}`")
    md.append(f"- manifest_parsed_count: `{success}`")
    md.append(f"- rsync_failed_count: `{fail}`")
    md.append(f"- connection_limit_error_count: `{conn}`")
    md.append("")
    md.append("## Targets")
    for r in records:
        md.append(
            f"- {r['target_id']} host=`{r['repo_host']}` status=`{r['rsync_list_status']}` "
            f"mft=`{r['manifest_filename']}` mft#=`{r['manifestNumber']}` failure=`{r['fetch_failure_type']}`"
        )
    md.append("")
    md.append("Semantic boundary: single-node live capture, not multi-probe same-window attribution.")
    (out / f"{capture_id}_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    check = "\n".join([
        "M23B_D_SAME_WINDOW_CAPTURE_ONCE=PASS" if records else "M23B_D_SAME_WINDOW_CAPTURE_ONCE=FAIL",
        f"capture_id = {capture_id}",
        f"capture_time_utc = {capture_time}",
        f"target_count = {len(records)}",
        f"manifest_parsed_count = {success}",
        f"rsync_failed_count = {fail}",
        f"connection_limit_error_count = {conn}",
        f"records_csv = {records_csv}",
        f"summary_md = {out / (capture_id + '_summary.md')}",
        "semantic_boundary = single_node_live_capture_not_multi_probe_same_window_attribution",
        "",
    ])
    (out / "M23B_D_SAME_WINDOW_CAPTURE_ONCE_CHECK.txt").write_text(check, encoding="utf-8")
    print(check)


if __name__ == "__main__":
    main()
