#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iter_jsonl(path: Path):
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield line_no, json.loads(line)
            except Exception as e:
                yield line_no, {"_parse_error": str(e), "_raw": line[:300]}


def run_cmd(cmd, timeout_sec: int):
    t0 = time.time()
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_sec,
        )
        return {
            "returncode": p.returncode,
            "duration_sec": round(time.time() - t0, 3),
            "stdout": p.stdout.decode("utf-8", errors="ignore"),
            "stderr": p.stderr.decode("utf-8", errors="ignore"),
        }
    except subprocess.TimeoutExpired as e:
        return {
            "returncode": -999,
            "duration_sec": round(time.time() - t0, 3),
            "stdout": "",
            "stderr": f"timeout_expired:{e}",
        }


def rsync_copy(src: Path, dst: Path, timeout_sec: int):
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        shutil.rmtree(dst)
    cmd = ["rsync", "-a", str(src) + "/", str(dst) + "/"]
    return run_cmd(cmd, timeout_sec=timeout_sec)


def parse_modes(modes: str):
    out = []
    for x in modes.split(","):
        x = x.strip()
        if x:
            out.append(x)
    valid = {"fresh_cache", "warm_cache", "stale_cache"}
    bad = [x for x in out if x not in valid]
    if bad:
        raise SystemExit(f"Unsupported modes: {bad}; valid={sorted(valid)}")
    return out


def normalize_asn(x):
    if x is None:
        return None
    s = str(x)
    if s.upper().startswith("AS"):
        return s.upper()
    return "AS" + s


def normalize_maxlen(x):
    if x is None:
        return None
    return str(x)


def load_jsonext_vrps(path: Path):
    if not path.exists():
        return {}

    try:
        obj = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return {}

    idx = {}
    for r in obj.get("roas", []):
        afi = "ipv6" if ":" in str(r.get("prefix", "")) else "ipv4"
        tal = None
        source_uri = None
        source_type = None

        src = r.get("source") or []
        if src and isinstance(src, list):
            s0 = src[0]
            tal = s0.get("tal")
            source_uri = s0.get("uri")
            source_type = s0.get("type")

        key = "|".join([
            afi,
            str(tal),
            str(r.get("prefix")),
            str(r.get("asn")).replace("AS", ""),
            str(r.get("maxLength")),
        ])

        idx[key] = {
            "afi": afi,
            "tal": tal,
            "prefix": r.get("prefix"),
            "asn": r.get("asn"),
            "maxLength": str(r.get("maxLength")),
            "source_uri": source_uri,
            "source_type": source_type,
        }
    return idx


def make_key_from_plan(rec):
    asn = str(rec.get("asn") or "")
    asn_num = asn.replace("AS", "").replace("as", "")
    return "|".join([
        str(rec.get("afi")),
        str(rec.get("tal")),
        str(rec.get("prefix")),
        str(asn_num),
        str(rec.get("maxLength")),
    ])


def select_plan_records(plan_path: Path, max_candidates: int, modes):
    seen_candidates = []
    selected = []

    for _, rec in iter_jsonl(plan_path):
        if not isinstance(rec, dict) or rec.get("_parse_error"):
            continue

        mode = rec.get("cache_mode")
        if mode not in modes:
            continue

        key = rec.get("vrp_key")
        if key not in seen_candidates:
            if len(seen_candidates) >= max_candidates:
                continue
            seen_candidates.append(key)

        if key in seen_candidates:
            selected.append(rec)

    return selected, seen_candidates


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--m21-run-dir", required=True)
    ap.add_argument("--a7-plan-jsonl", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--cache-source", default=str(Path.home() / ".rpki-cache"))
    ap.add_argument("--max-candidates", type=int, default=3)
    ap.add_argument("--modes", default="stale_cache,warm_cache,fresh_cache")
    ap.add_argument("--timeout-sec", type=int, default=2400)
    args = ap.parse_args()

    m21 = Path(args.m21_run_dir)
    plan_path = Path(args.a7_plan_jsonl)
    out_dir = Path(args.out_dir)
    cache_source = Path(args.cache_source).expanduser()
    modes = parse_modes(args.modes)

    out_dir.mkdir(parents=True, exist_ok=True)
    checks = m21 / "checks"
    logs = m21 / "logs"
    checks.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)

    cache_root = out_dir / "isolated_caches"
    vrp_root = out_dir / "vrp_outputs"
    cache_root.mkdir(parents=True, exist_ok=True)
    vrp_root.mkdir(parents=True, exist_ok=True)

    replay_records_path = out_dir / "m21_a7b_actual_cache_replay_records.jsonl"
    summary_jsonl_path = out_dir / "m21_a7b_cache_replay_summary.jsonl"
    summary_json_path = out_dir / "m21_a7b_cache_replay_summary.json"
    check_path = checks / "M21_A7B_ACTUAL_CACHE_REPLAY_SMALL_BATCH.txt"

    selected_records, selected_keys = select_plan_records(plan_path, args.max_candidates, modes)

    counters = Counter()
    counters["candidate_selected"] = len(selected_keys)
    counters["plan_records_selected"] = len(selected_records)

    if not cache_source.exists():
        raise SystemExit(f"cache-source not found: {cache_source}")

    mode_output_index = {}

    with replay_records_path.open("w", encoding="utf-8") as rec_out:
        for mode in modes:
            counters[f"mode_attempted:{mode}"] += 1

            mode_cache = cache_root / mode
            mode_vrp = vrp_root / f"{mode}.jsonext.json"

            # Prepare cache according to mode.
            prep_status = "unknown"
            prep_detail = {}

            if mode == "fresh_cache":
                if mode_cache.exists():
                    shutil.rmtree(mode_cache)
                mode_cache.mkdir(parents=True, exist_ok=True)
                prep_status = "new_empty_cache"
            elif mode in ("warm_cache", "stale_cache"):
                prep = rsync_copy(cache_source, mode_cache, timeout_sec=600)
                prep_detail = prep
                prep_status = "copied_existing_cache" if prep["returncode"] == 0 else "copy_failed"
            else:
                prep_status = "unsupported"

            if prep_status == "copy_failed":
                cmd_res = {
                    "returncode": -998,
                    "duration_sec": prep_detail.get("duration_sec"),
                    "stdout": prep_detail.get("stdout", ""),
                    "stderr": prep_detail.get("stderr", ""),
                }
            else:
                # Routinator invocation.
                if mode == "stale_cache":
                    cmd = [
                        "routinator",
                        "--repository-dir", str(mode_cache),
                        "vrps",
                        "--noupdate",
                        "--format", "jsonext",
                        "--output", str(mode_vrp),
                    ]
                elif mode == "warm_cache":
                    cmd = [
                        "routinator",
                        "--repository-dir", str(mode_cache),
                        "vrps",
                        "--format", "jsonext",
                        "--output", str(mode_vrp),
                    ]
                else:
                    cmd = [
                        "routinator",
                        "--repository-dir", str(mode_cache),
                        "--fresh",
                        "vrps",
                        "--format", "jsonext",
                        "--output", str(mode_vrp),
                    ]

                cmd_res = run_cmd(cmd, timeout_sec=args.timeout_sec)

            replay_status = "success" if cmd_res["returncode"] == 0 and mode_vrp.exists() and mode_vrp.stat().st_size > 0 else "failed"
            counters[f"replay_status:{mode}:{replay_status}"] += 1

            vrp_index = load_jsonext_vrps(mode_vrp) if replay_status == "success" else {}
            mode_output_index[mode] = vrp_index

            replay_rec = {
                "schema": "s3.m21.a7b.actual_cache_replay_mode_record.v1",
                "cache_mode": mode,
                "cache_dir": str(mode_cache),
                "vrp_output_jsonext": str(mode_vrp),
                "prep_status": prep_status,
                "replay_status": replay_status,
                "returncode": cmd_res["returncode"],
                "duration_sec": cmd_res["duration_sec"],
                "stderr_tail": cmd_res.get("stderr", "")[-2000:],
                "stdout_tail": cmd_res.get("stdout", "")[-2000:],
                "jsonext_vrp_index_count": len(vrp_index),
                "semantic_boundary": "actual_live_cache_replay_not_same_input_snapshot",
                "strong_causal_claim_allowed": False,
            }
            rec_out.write(json.dumps(replay_rec, ensure_ascii=False, sort_keys=True) + "\n")

    with summary_jsonl_path.open("w", encoding="utf-8") as out:
        for rec in selected_records:
            mode = rec.get("cache_mode")
            vrp_key = rec.get("vrp_key")
            expected_key = make_key_from_plan(rec)

            vrp_index = mode_output_index.get(mode, {})
            found_by_key = vrp_index.get(expected_key)

            found = found_by_key is not None
            if found:
                counters[f"candidate_found:{mode}"] += 1
                replay_presence_status = "candidate_vrp_present_in_replay_output"
            else:
                counters[f"candidate_missing:{mode}"] += 1
                replay_presence_status = "candidate_vrp_missing_in_replay_output"

            out_rec = {
                "schema": "s3.m21.a7b.cache_replay_candidate_result.v1",
                "vrp_key": vrp_key,
                "expected_lookup_key": expected_key,
                "cache_mode": mode,
                "replay_presence_status": replay_presence_status,
                "candidate_found_in_jsonext": found,
                "replayed_source_uri": found_by_key.get("source_uri") if found_by_key else None,
                "replayed_source_type": found_by_key.get("source_type") if found_by_key else None,

                "afi": rec.get("afi"),
                "tal": rec.get("tal"),
                "prefix": rec.get("prefix"),
                "asn": rec.get("asn"),
                "maxLength": rec.get("maxLength"),
                "roa_uri": rec.get("roa_uri"),
                "manifest_uri": rec.get("manifest_uri"),
                "manifestNumber": rec.get("manifestNumber"),
                "manifest_thisUpdate": rec.get("manifest_thisUpdate"),
                "manifest_nextUpdate": rec.get("manifest_nextUpdate"),
                "nearest_window_id": rec.get("nearest_window_id"),
                "nearest_window_delta_sec": rec.get("nearest_window_delta_sec"),
                "a4_alignment_confidence": rec.get("a4_alignment_confidence"),
                "expected_diff_hypothesis": rec.get("expected_diff_hypothesis"),

                "semantic_boundary": "actual_live_cache_replay_not_same_input_snapshot",
                "strong_causal_claim_allowed": False,
            }
            out.write(json.dumps(out_rec, ensure_ascii=False, sort_keys=True) + "\n")
            counters["candidate_result_records_written"] += 1

    summary = {
        "schema": "s3.m21.a7b.actual_cache_replay_small_batch_summary.v1",
        "generated_at_utc": utc_now(),
        "m21_run_dir": str(m21),
        "a7_plan_jsonl": str(plan_path),
        "cache_source": str(cache_source),
        "modes": modes,
        "max_candidates": args.max_candidates,
        "counters": dict(counters),
        "outputs": {
            "replay_records_jsonl": str(replay_records_path),
            "candidate_result_jsonl": str(summary_jsonl_path),
            "summary_json": str(summary_json_path),
            "check_txt": str(check_path),
        },
        "interpretation": {
            "what_was_executed": "Routinator was executed with isolated repository directories for selected cache modes.",
            "important_boundary": "This is live cache replay. It is not a same-input repository snapshot replay.",
            "how_to_interpret": "Presence or absence of selected VRPs in each mode is evidence of cache/reachability sensitivity, not final causal attribution.",
        },
        "semantic_boundary": "actual_live_cache_replay_not_same_input_snapshot",
        "strong_causal_claim_allowed": False,
        "next_stage": "M21_A7C_COMPARE_CACHE_REPLAY_RESULTS_AND_SELECT_CASES",
    }
    summary_json_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "M21_A7B_ACTUAL_CACHE_REPLAY_SMALL_BATCH=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"candidate_selected = {counters['candidate_selected']}",
        f"plan_records_selected = {counters['plan_records_selected']}",
        f"candidate_result_records_written = {counters['candidate_result_records_written']}",
        f"replay_status_fresh_cache_success = {counters['replay_status:fresh_cache:success']}",
        f"replay_status_warm_cache_success = {counters['replay_status:warm_cache:success']}",
        f"replay_status_stale_cache_success = {counters['replay_status:stale_cache:success']}",
        f"candidate_found_fresh_cache = {counters['candidate_found:fresh_cache']}",
        f"candidate_found_warm_cache = {counters['candidate_found:warm_cache']}",
        f"candidate_found_stale_cache = {counters['candidate_found:stale_cache']}",
        f"candidate_missing_fresh_cache = {counters['candidate_missing:fresh_cache']}",
        f"candidate_missing_warm_cache = {counters['candidate_missing:warm_cache']}",
        f"candidate_missing_stale_cache = {counters['candidate_missing:stale_cache']}",
        f"replay_records_jsonl = {replay_records_path}",
        f"candidate_result_jsonl = {summary_jsonl_path}",
        f"summary_json = {summary_json_path}",
        "semantic_boundary = actual_live_cache_replay_not_same_input_snapshot",
        "strong_causal_claim_allowed = False",
        "next_stage = M21_A7C_COMPARE_CACHE_REPLAY_RESULTS_AND_SELECT_CASES",
    ]
    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
