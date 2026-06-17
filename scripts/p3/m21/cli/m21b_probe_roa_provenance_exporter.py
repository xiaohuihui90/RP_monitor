#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import gzip
import hashlib
import ipaddress
import json
import os
import tarfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from asn1crypto import cms, core


class ROAIPAddress(core.Sequence):
    _fields = [
        ("address", core.BitString),
        ("maxLength", core.Integer, {"optional": True}),
    ]


class ROAIPAddresses(core.SequenceOf):
    _child_spec = ROAIPAddress


class ROAIPAddressFamily(core.Sequence):
    _fields = [
        ("addressFamily", core.OctetString),
        ("addresses", ROAIPAddresses),
    ]


class ROAIPAddressFamilies(core.SequenceOf):
    _child_spec = ROAIPAddressFamily


class RouteOriginAttestation(core.Sequence):
    _fields = [
        ("version", core.Integer, {"explicit": 0, "default": 0}),
        ("asID", core.Integer),
        ("ipAddrBlocks", ROAIPAddressFamilies),
    ]


REQUIRED_TAS = ["afrinic", "apnic", "arin", "lacnic", "ripe"]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_vrp_key(asn: int, prefix: str, max_length: int, ta: str) -> str:
    obj = {
        "asn": int(asn),
        "prefix": str(prefix),
        "max_length": int(max_length),
        "ta": str(ta).lower(),
    }
    s = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(s.encode("utf-8")).hexdigest()


def read_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            n += 1
    return n


def load_affected_set(path: Path) -> tuple[dict[tuple[int, str, int], list[dict]], dict[str, dict]]:
    by_tuple_no_ta: dict[tuple[int, str, int], list[dict]] = defaultdict(list)
    by_key: dict[str, dict] = {}

    for row in read_jsonl(path):
        asn = int(row["asn"])
        prefix = str(row["prefix"])
        max_length = int(row["max_length"])
        ta = str(row["ta"]).lower()
        key = row.get("vrp_key") or canonical_vrp_key(asn, prefix, max_length, ta)

        row["vrp_key"] = key
        row["ta"] = ta

        by_tuple_no_ta[(asn, prefix, max_length)].append(row)
        by_key[key] = row

    return by_tuple_no_ta, by_key


def guess_ta_from_text(text: str) -> tuple[str, str, str]:
    x = text.lower()

    for ta in REQUIRED_TAS:
        if ta in x:
            return ta, "uri_text", "medium"

    # 常见 RIR repo hint。这里只做弱启发，不作为强归因。
    if "rpki-repo.registro.br" in x:
        return "lacnic", "repo_host_hint", "medium"
    if "rpki.ripe.net" in x:
        return "ripe", "repo_host_hint", "medium"
    if "rpki.apnic.net" in x or "rpki-repository.nic.ad.jp" in x:
        return "apnic", "repo_host_hint", "medium"
    if "arin.net" in x:
        return "arin", "repo_host_hint", "medium"
    if "afrinic" in x:
        return "afrinic", "repo_host_hint", "medium"

    return "unknown", "unknown", "unknown"


def source_path_to_object_uri(path: Path) -> str:
    s = str(path)

    markers = [
        "/.rpki-cache/",
        "/rpki-cache/",
    ]

    for m in markers:
        if m in s:
            return "cache://" + s.split(m, 1)[1]

    return "file://" + s


def iter_roa_files(cache_roots: list[Path], max_files: int = 0) -> Iterable[Path]:
    seen = set()
    count = 0

    for root in cache_roots:
        if not root.exists():
            continue

        for p in root.rglob("*.roa"):
            try:
                rp = p.resolve()
            except Exception:
                rp = p

            key = str(rp)
            if key in seen:
                continue
            seen.add(key)

            yield p
            count += 1

            if max_files and count >= max_files:
                return


def extract_roa_econtent(raw: bytes) -> tuple[bytes, str]:
    ci = cms.ContentInfo.load(raw)

    if ci["content_type"].native != "signed_data":
        raise ValueError(f"not signed_data: {ci['content_type'].native}")

    sd = ci["content"]
    eci = sd["encap_content_info"]

    content_type = eci["content_type"].dotted
    content = eci["content"]

    if content.native is None:
        raise ValueError("missing eContent")

    econtent = content.native
    if not isinstance(econtent, bytes):
        econtent = bytes(econtent)

    return econtent, content_type


def bitstring_to_prefix(bitstr: core.BitString, afi: int) -> tuple[str, int]:
    contents = bitstr.contents
    if not contents:
        raise ValueError("empty bitstring")

    unused_bits = contents[0]
    data = contents[1:]
    prefix_len = len(data) * 8 - int(unused_bits)

    if afi == 1:
        total_bytes = 4
        addr_cls = ipaddress.IPv4Address
        net_cls = ipaddress.IPv4Network
    elif afi == 2:
        total_bytes = 16
        addr_cls = ipaddress.IPv6Address
        net_cls = ipaddress.IPv6Network
    else:
        raise ValueError(f"unsupported AFI: {afi}")

    padded = data + b"\x00" * max(0, total_bytes - len(data))
    padded = padded[:total_bytes]

    addr = addr_cls(padded)
    net = net_cls((addr, prefix_len), strict=False)

    return str(net), prefix_len


def parse_roa(raw: bytes) -> tuple[list[dict], dict]:
    econtent, content_type = extract_roa_econtent(raw)
    roa = RouteOriginAttestation.load(econtent)

    asn = int(roa["asID"].native)

    vrps = []
    for fam in roa["ipAddrBlocks"]:
        af_bytes = fam["addressFamily"].native
        if len(af_bytes) < 2:
            raise ValueError(f"invalid addressFamily: {af_bytes!r}")

        afi = int.from_bytes(af_bytes[:2], "big")

        for addr in fam["addresses"]:
            prefix, prefix_len = bitstring_to_prefix(addr["address"], afi)

            if "maxLength" in addr and addr["maxLength"].native is not None:
                max_length = int(addr["maxLength"].native)
            else:
                max_length = prefix_len

            vrps.append({
                "asn": asn,
                "prefix": prefix,
                "prefix_length": prefix_len,
                "max_length": max_length,
                "afi": afi,
            })

    meta = {
        "cms_econtent_type": content_type,
        "roa_vrp_count": len(vrps),
    }

    return vrps, meta


def make_archive(run_dir: Path, archive_path: Path) -> None:
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    if archive_path.exists():
        archive_path.unlink()

    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(run_dir, arcname=run_dir.name)

    h = hashlib.sha256()
    with archive_path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)

    archive_path.with_suffix(archive_path.suffix + ".sha256").write_text(
        f"{h.hexdigest()}  {archive_path}\n",
        encoding="utf-8",
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="M21-B probe-side ROA->VRP provenance exporter")
    ap.add_argument("--probe-id", required=True)
    ap.add_argument("--affected-vrp-set", required=True)
    ap.add_argument("--out-root", required=True)
    ap.add_argument("--max-files", type=int, default=0)
    ap.add_argument("--cache-root", action="append", default=[])
    args = ap.parse_args()

    probe_id = args.probe_id
    affected_path = Path(args.affected_vrp_set).resolve()
    out_root = Path(args.out_root).resolve()

    affected_by_tuple, affected_by_key = load_affected_set(affected_path)

    if args.cache_root:
        cache_roots = [Path(x).expanduser() for x in args.cache_root]
    else:
        cache_roots = [
            Path.home() / ".rpki-cache",
            Path("/var/lib/routinator/rpki-cache"),
        ]

    run_id = f"m21b_probe_roa_provenance_{probe_id}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    run_dir = out_root / "history" / run_id
    out_dir = run_dir / "outputs"
    idx_dir = run_dir / "indexes"
    chk_dir = run_dir / "checks"
    log_dir = run_dir / "logs"

    for d in [out_dir, idx_dir, chk_dir, log_dir]:
        d.mkdir(parents=True, exist_ok=True)

    scanned = 0
    parsed_success = 0
    parsed_error = 0
    matched_record_count = 0

    by_error = Counter()
    by_ta_guess = Counter()
    by_affected_ta = Counter()
    by_affected_vrp_key = Counter()

    match_rows = []
    error_rows = []
    seen_match_keys = set()

    for path in iter_roa_files(cache_roots, max_files=args.max_files):
        scanned += 1

        try:
            raw = path.read_bytes()
            raw_sha256 = sha256_bytes(raw)
            raw_size = len(raw)
            object_uri = source_path_to_object_uri(path)
            ta_guess, ta_method, ta_conf = guess_ta_from_text(str(path))

            vrps, meta = parse_roa(raw)
            parsed_success += 1
            by_ta_guess[ta_guess] += 1

            for v in vrps:
                lookup_key = (int(v["asn"]), str(v["prefix"]), int(v["max_length"]))
                affected_rows = affected_by_tuple.get(lookup_key, [])

                if not affected_rows:
                    continue

                for aff in affected_rows:
                    affected_ta = aff["ta"]
                    affected_key = aff["vrp_key"]

                    dedupe = (raw_sha256, affected_key, str(path))
                    if dedupe in seen_match_keys:
                        continue
                    seen_match_keys.add(dedupe)

                    exact_vrp_key_with_affected_ta = canonical_vrp_key(
                        v["asn"], v["prefix"], v["max_length"], affected_ta
                    )

                    row = {
                        "schema": "s3.m21b.probe_roa_vrp_provenance_match.v1",
                        "probe_id": probe_id,
                        "run_id": run_id,
                        "created_at_utc": utc_now_iso(),

                        "source_path": str(path),
                        "object_uri": object_uri,
                        "raw_sha256": raw_sha256,
                        "raw_size_bytes": raw_size,

                        "parse_status": "success",
                        "cms_econtent_type": meta.get("cms_econtent_type"),
                        "roa_vrp_count": meta.get("roa_vrp_count"),

                        "ta_guess": ta_guess,
                        "ta_guess_method": ta_method,
                        "ta_confidence": ta_conf,

                        "roa_tuple": {
                            "asn": int(v["asn"]),
                            "prefix": str(v["prefix"]),
                            "prefix_length": int(v["prefix_length"]),
                            "max_length": int(v["max_length"]),
                            "afi": int(v["afi"]),
                        },

                        "affected_vrp_tuple": {
                            "asn": int(aff["asn"]),
                            "prefix": str(aff["prefix"]),
                            "max_length": int(aff["max_length"]),
                            "ta": affected_ta,
                        },
                        "affected_vrp_key": affected_key,
                        "exact_vrp_key_with_affected_ta": exact_vrp_key_with_affected_ta,
                        "match_mode": "asn_prefix_maxlen_match_ta_from_affected_set",
                        "matched_pairs": aff.get("pairs", []),
                        "matched_sides": aff.get("sides", []),
                    }

                    match_rows.append(row)
                    matched_record_count += 1
                    by_affected_ta[affected_ta] += 1
                    by_affected_vrp_key[affected_key] += 1

        except Exception as e:
            parsed_error += 1
            err = type(e).__name__ + ": " + str(e)
            by_error[err[:180]] += 1

            if len(error_rows) < 200:
                error_rows.append({
                    "schema": "s3.m21b.probe_roa_parse_error.v1",
                    "probe_id": probe_id,
                    "source_path": str(path),
                    "error": err,
                })

    match_index = idx_dir / "m21b_probe_roa_provenance_matches.jsonl"
    error_index = idx_dir / "m21b_probe_roa_parse_errors_sample.jsonl"

    write_jsonl(match_index, match_rows)
    write_jsonl(error_index, error_rows)

    matched_unique_affected = set(by_affected_vrp_key.keys())
    affected_total = len(affected_by_key)

    summary = {
        "schema": "s3.m21b.probe_roa_provenance_summary.v1",
        "status": "PASS",
        "probe_id": probe_id,
        "run_id": run_id,
        "created_at_utc": utc_now_iso(),

        "affected_vrp_set": str(affected_path),
        "affected_vrp_count": affected_total,
        "matched_unique_affected_vrp_count": len(matched_unique_affected),
        "matched_unique_affected_vrp_ratio": (len(matched_unique_affected) / affected_total) if affected_total else None,

        "cache_roots": [str(x) for x in cache_roots],
        "max_files": args.max_files,
        "scanned_roa_file_count": scanned,
        "parsed_success_count": parsed_success,
        "parsed_error_count": parsed_error,
        "matched_record_count": matched_record_count,

        "by_ta_guess": dict(by_ta_guess),
        "by_affected_ta": dict(by_affected_ta),
        "by_error_top": by_error.most_common(20),

        "match_index": str(match_index),
        "error_sample_index": str(error_index),

        "important_boundary": [
            "This is probe-side current-cache provenance, not yet a strong snapshot-time object attribution.",
            "TA is taken from affected VRP set for matching; ta_guess from path is heuristic only.",
            "Strong attribution requires collector-side merge and object/manifest context join in M21-C."
        ],
    }

    write_json(out_dir / "M21B_probe_roa_provenance_summary.json", summary)

    check_text = "\n".join([
        "M21B_PROBE_ROA_PROVENANCE_EXPORTER=PASS",
        "",
        f"probe_id = {probe_id}",
        f"run_id = {run_id}",
        f"affected_vrp_count = {affected_total}",
        f"matched_unique_affected_vrp_count = {len(matched_unique_affected)}",
        f"matched_unique_affected_vrp_ratio = {summary['matched_unique_affected_vrp_ratio']}",
        f"scanned_roa_file_count = {scanned}",
        f"parsed_success_count = {parsed_success}",
        f"parsed_error_count = {parsed_error}",
        f"matched_record_count = {matched_record_count}",
        f"by_affected_ta = {dict(by_affected_ta)}",
        f"summary_path = {out_dir / 'M21B_probe_roa_provenance_summary.json'}",
        f"match_index = {match_index}",
    ]) + "\n"

    (chk_dir / "M21B_probe_roa_provenance_check.txt").write_text(check_text, encoding="utf-8")
    print(check_text)

    latest_dir = out_root / "latest"
    latest_dir.mkdir(parents=True, exist_ok=True)
    write_json(latest_dir / "M21B_probe_roa_provenance_summary.json", summary)

    exports_dir = out_root / "exports"
    archive_path = exports_dir / f"{run_id}.tar.gz"
    make_archive(run_dir, archive_path)

    print(f"archive_path = {archive_path}")
    print(f"archive_sha256 = {archive_path}.sha256")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
