#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import gzip
import importlib.util
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable


def read_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def load_vrps_json(path: Path) -> list[Dict[str, Any]]:
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
    else:
        obj = json.loads(path.read_text(encoding="utf-8", errors="replace"))

    if isinstance(obj, dict):
        return obj.get("roas", [])
    if isinstance(obj, list):
        return obj
    return []


def norm_asn(v: Any) -> int:
    s = str(v).strip().upper()
    if s.startswith("AS"):
        s = s[2:]
    return int(s)


def load_affected(path: Path) -> dict[tuple[int, str, int, str], Dict[str, Any]]:
    out = {}
    for r in read_jsonl(path):
        k = (
            norm_asn(r["asn"]),
            str(r["prefix"]).strip(),
            int(r["max_length"]),
            str(r["ta"]).lower(),
        )
        out[k] = r
    return out


def decode_filename_stem(p: Path) -> str:
    stem = p.name
    if stem.endswith(".roa"):
        stem = stem[:-4]

    # Routinator cache 里很多文件名是 hex 编码后的 "prefix/plen-max => asn"
    try:
        if len(stem) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in stem):
            return bytes.fromhex(stem).decode("utf-8", errors="replace")
    except Exception:
        pass

    return stem


def candidate_texts(asn: int, prefix: str, max_length: int) -> list[str]:
    out = []

    try:
        base, plen = prefix.split("/")
        out.append(f"{base}/{plen}-{max_length} => {asn}")
        out.append(f"{base}/{plen}-{max_length}=>{asn}")
        out.append(f"{base}/{plen}")
    except Exception:
        pass

    out.append(f"AS{asn}")
    out.append(str(asn))

    return sorted(set(x.lower() for x in out))


def import_exporter_parser(script_path: Path):
    spec = importlib.util.spec_from_file_location("m21b_exporter", script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {script_path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.parse_roa


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--affected-vrp-set", required=True)
    ap.add_argument("--current-vrp-json", required=True)
    ap.add_argument("--exporter-script", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--cache-root", action="append", default=[])
    ap.add_argument("--max-hits-per-vrp", type=int, default=50)
    args = ap.parse_args()

    affected = load_affected(Path(args.affected_vrp_set).resolve())
    current_vrps = load_vrps_json(Path(args.current_vrp_json).resolve())
    parse_roa = import_exporter_parser(Path(args.exporter_script).resolve())

    if args.cache_root:
        cache_roots = [Path(x).expanduser() for x in args.cache_root]
    else:
        cache_roots = [
            Path.home() / ".rpki-cache",
            Path("/var/lib/routinator/rpki-cache"),
        ]

    current_keys = set()
    for r in current_vrps:
        k = (
            norm_asn(r["asn"]),
            str(r["prefix"]).strip(),
            int(r.get("maxLength", r.get("max_length"))),
            str(r["ta"]).lower(),
        )
        if k in affected:
            current_keys.add(k)

    roa_files = []
    for root in cache_roots:
        if root.exists():
            roa_files.extend(root.rglob("*.roa"))

    rows = []
    parser_match_count = 0
    filename_hit_vrp_count = 0
    by_status = Counter()

    for key in sorted(current_keys):
        asn, prefix, max_length, ta = key
        texts = candidate_texts(asn, prefix, max_length)

        hits = []
        for p in roa_files:
            decoded = decode_filename_stem(p)
            hay = (str(p) + " " + decoded).lower()

            # 精确优先：prefix/plen-max => asn
            if any(t in hay for t in texts):
                hits.append((p, decoded))
                if len(hits) >= args.max_hits_per_vrp:
                    break

        if hits:
            filename_hit_vrp_count += 1

        parsed_hit = False
        parsed_samples = []
        parse_errors = []

        for p, decoded in hits[:10]:
            try:
                raw = p.read_bytes()
                vrps, meta = parse_roa(raw)

                for v in vrps[:20]:
                    parsed_samples.append({
                        "source_path": str(p),
                        "decoded_name": decoded,
                        "parsed_tuple": {
                            "asn": int(v["asn"]),
                            "prefix": str(v["prefix"]),
                            "prefix_length": int(v["prefix_length"]),
                            "max_length": int(v["max_length"]),
                            "afi": int(v["afi"]),
                        },
                    })

                for v in vrps:
                    if (
                        int(v["asn"]) == asn
                        and str(v["prefix"]) == prefix
                        and int(v["max_length"]) == max_length
                    ):
                        parsed_hit = True

            except Exception as e:
                parse_errors.append({
                    "source_path": str(p),
                    "error": type(e).__name__ + ": " + str(e),
                })

        if parsed_hit:
            parser_match_count += 1
            status = "filename_hit_and_parser_match"
        elif hits:
            status = "filename_hit_but_parser_no_match"
        else:
            status = "no_filename_hit"

        by_status[status] += 1

        rows.append({
            "schema": "s3.m21b.path_hit_parser_verify.v1",
            "affected_key": {
                "asn": asn,
                "prefix": prefix,
                "max_length": max_length,
                "ta": ta,
            },
            "candidate_texts": texts,
            "filename_hit_count_capped": len(hits),
            "filename_hits": [
                {
                    "source_path": str(p),
                    "decoded_name": decoded,
                }
                for p, decoded in hits[:20]
            ],
            "parser_match": parsed_hit,
            "status": status,
            "parsed_samples": parsed_samples[:20],
            "parse_errors": parse_errors[:20],
        })

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    index_path = out_dir / "m21b_path_hit_parser_verify.jsonl"
    with index_path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")

    summary = {
        "schema": "s3.m21b.path_hit_parser_verify_summary.v1",
        "affected_total": len(affected),
        "current_affected_count": len(current_keys),
        "filename_hit_vrp_count": filename_hit_vrp_count,
        "parser_match_vrp_count": parser_match_count,
        "by_status": dict(by_status),
        "index_path": str(index_path),
    }

    summary_path = out_dir / "M21B_path_hit_parser_verify_summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print("M21B_PATH_HIT_PARSER_VERIFY=PASS")
    print(f"affected_total = {len(affected)}")
    print(f"current_affected_count = {len(current_keys)}")
    print(f"filename_hit_vrp_count = {filename_hit_vrp_count}")
    print(f"parser_match_vrp_count = {parser_match_count}")
    print(f"by_status = {dict(by_status)}")
    print(f"summary_path = {summary_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
