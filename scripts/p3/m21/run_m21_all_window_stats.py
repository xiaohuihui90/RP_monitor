#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timezone


WINDOW_RE = re.compile(r"win_(\d{8}T\d{6}Z)_10m")


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_window_id(text: str):
    m = WINDOW_RE.search(text or "")
    if not m:
        return None, None
    wid = f"win_{m.group(1)}_10m"
    dt = datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    return wid, dt


def fmt(dt):
    return dt.isoformat().replace("+00:00", "Z") if dt else None


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None


def iter_jsonl(path: Path):
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def collect_relation_like_objects(obj, out: Counter):
    if isinstance(obj, dict):
        if any(k in obj for k in ["session_relation", "serial_relation", "notif_digest_relation"]):
            rel = "|".join([
                str(obj.get("session_relation")),
                str(obj.get("serial_relation")),
                str(obj.get("notif_digest_relation")),
            ])
            out[rel] += 1
        for v in obj.values():
            collect_relation_like_objects(v, out)
    elif isinstance(obj, list):
        for v in obj:
            collect_relation_like_objects(v, out)


def collect_pp_status(obj, pp_counter: Counter, relation_counter: Counter):
    if not isinstance(obj, dict):
        return

    advertised = obj.get("advertised_view")
    if not isinstance(advertised, dict):
        return

    pp_status = advertised.get("pp_status")
    if not isinstance(pp_status, dict):
        return

    for pp, rec in pp_status.items():
        pp_counter[str(pp)] += 1
        if isinstance(rec, dict):
            rel = "|".join([
                str(rec.get("session_relation")),
                str(rec.get("serial_relation")),
                str(rec.get("notif_digest_relation")),
            ])
            relation_counter[rel] += 1


def scan_m245(m245_root: Path):
    result = {
        "root": str(m245_root),
        "dir_count": 0,
        "unique_window_count": 0,
        "window_min_utc": None,
        "window_max_utc": None,
        "duplicate_windows": {},
        "window_top20": [],
        "files_available": {},
        "pp_status_top20": [],
        "notification_relation_top20": [],
        "generic_relation_top20": [],
    }

    if not m245_root.exists():
        result["missing"] = True
        return result

    dirs = [p for p in m245_root.iterdir() if p.is_dir()]
    result["dir_count"] = len(dirs)

    window_ids = []
    window_times = []
    file_avail = Counter()
    pp_counter = Counter()
    relation_counter = Counter()
    generic_relation_counter = Counter()

    for d in dirs:
        wid, dt = parse_window_id(d.name)
        if wid:
            window_ids.append(wid)
        if dt:
            window_times.append(dt)

        status = d / "outputs/M245_three_layer_status_matrix.json"
        mapping = d / "outputs/M245_mapping_context.json"
        validator = d / "outputs/M245_merged_validator_context.json"

        if status.exists():
            file_avail["status_matrix"] += 1
            obj = read_json(status)
            if obj is not None:
                collect_pp_status(obj, pp_counter, relation_counter)
                collect_relation_like_objects(obj, generic_relation_counter)

        if mapping.exists():
            file_avail["mapping_context"] += 1

        if validator.exists():
            file_avail["merged_validator_context"] += 1

    c = Counter(window_ids)
    result["unique_window_count"] = len(c)
    result["duplicate_windows"] = {k: v for k, v in c.items() if v > 1}
    result["window_top20"] = c.most_common(20)

    if window_times:
        result["window_min_utc"] = fmt(min(window_times))
        result["window_max_utc"] = fmt(max(window_times))

    result["files_available"] = dict(file_avail)
    result["pp_status_top20"] = pp_counter.most_common(20)
    result["notification_relation_top20"] = relation_counter.most_common(20)
    result["generic_relation_top20"] = generic_relation_counter.most_common(20)
    return result


def scan_m17(m17_root: Path):
    result = {
        "root": str(m17_root),
        "dir_count": 0,
        "unique_window_count": 0,
        "window_min_utc": None,
        "window_max_utc": None,
        "window_top20": [],
        "check_file_count": 0,
        "summary_file_count": 0,
        "metric_top50": [],
    }

    if not m17_root.exists():
        result["missing"] = True
        return result

    dirs = [p for p in m17_root.iterdir() if p.is_dir()]
    result["dir_count"] = len(dirs)

    window_ids = []
    window_times = []
    metrics = Counter()

    patterns = [
        re.compile(r"([A-Za-z0-9_]*diff[A-Za-z0-9_]*count)\s*[:=]\s*([0-9]+)"),
        re.compile(r"(candidate_count)\s*[:=]\s*([0-9]+)"),
        re.compile(r"(record_count)\s*[:=]\s*([0-9]+)"),
        re.compile(r"(records_written)\s*[:=]\s*([0-9]+)"),
        re.compile(r"(vrp_count)\s*[:=]\s*([0-9]+)"),
    ]

    for d in dirs:
        wid, dt = parse_window_id(d.name)
        if wid:
            window_ids.append(wid)
        if dt:
            window_times.append(dt)

        files = list((d / "checks").glob("*.txt")) + list((d / "outputs").glob("*.txt"))
        result["check_file_count"] += len(list((d / "checks").glob("*.txt")))
        result["summary_file_count"] += len(list((d / "outputs").glob("*.txt")))

        for f in files:
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for pat in patterns:
                for m in pat.finditer(text):
                    key, val = m.group(1), int(m.group(2))
                    metrics[key] += val

    c = Counter(window_ids)
    result["unique_window_count"] = len(c)
    result["window_top20"] = c.most_common(20)

    if window_times:
        result["window_min_utc"] = fmt(min(window_times))
        result["window_max_utc"] = fmt(max(window_times))

    result["metric_top50"] = metrics.most_common(50)
    return result


def scan_run_level_roots(roots: dict[str, Path]):
    out = {}
    for name, root in roots.items():
        item = {
            "root": str(root),
            "dir_count": 0,
            "sample_dirs": [],
            "time_min_from_dirname": None,
            "time_max_from_dirname": None,
        }

        if not root.exists():
            item["missing"] = True
            out[name] = item
            continue

        dirs = [p for p in root.iterdir() if p.is_dir()]
        item["dir_count"] = len(dirs)
        item["sample_dirs"] = [p.name for p in dirs[:20]]

        times = []
        for d in dirs:
            for m in re.finditer(r"(\d{8}T\d{6}Z)", d.name):
                try:
                    times.append(datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc))
                except Exception:
                    pass

        if times:
            item["time_min_from_dirname"] = fmt(min(times))
            item["time_max_from_dirname"] = fmt(max(times))

        out[name] = item
    return out


def scan_a8(a8_records: Path):
    result = {
        "path": str(a8_records),
        "record_count": 0,
        "tal_top20": [],
        "asn_top20": [],
        "manifestNumber_top20": [],
        "window_top20": [],
        "notification_relation_top20": [],
        "evidence_completeness": {},
        "nearest_delta_sec": {},
    }

    if not a8_records.exists():
        result["missing"] = True
        return result

    tal = Counter()
    asn = Counter()
    mft = Counter()
    win = Counter()
    notif_rel = Counter()
    completeness = Counter()
    deltas = []

    for o in iter_jsonl(a8_records):
        result["record_count"] += 1
        tal[o.get("tal")] += 1
        asn[o.get("asn")] += 1
        mft[str(o.get("manifestNumber"))] += 1
        win[o.get("window_id")] += 1

        for rel, count in o.get("notification_like_relation_top") or []:
            notif_rel[rel] += int(count)

        for k in [
            "jsonext_available",
            "manifest_context_available",
            "notification_context_available",
            "validator_timing_available",
        ]:
            if o.get(k):
                completeness[k] += 1

        v = o.get("nearest_window_delta_sec")
        if isinstance(v, (int, float)):
            deltas.append(v)

    result["tal_top20"] = tal.most_common(20)
    result["asn_top20"] = asn.most_common(20)
    result["manifestNumber_top20"] = mft.most_common(20)
    result["window_top20"] = win.most_common(20)
    result["notification_relation_top20"] = notif_rel.most_common(20)

    if result["record_count"]:
        result["evidence_completeness"] = {
            k: {
                "count": completeness[k],
                "ratio": round(completeness[k] / result["record_count"], 4),
            }
            for k in [
                "jsonext_available",
                "manifest_context_available",
                "notification_context_available",
                "validator_timing_available",
            ]
        }

    deltas.sort()
    if deltas:
        def pct(q):
            return deltas[int((len(deltas)-1) * q)]
        result["nearest_delta_sec"] = {
            "count": len(deltas),
            "min": deltas[0],
            "median": pct(0.5),
            "p75": pct(0.75),
            "p90": pct(0.9),
            "p95": pct(0.95),
            "max": deltas[-1],
        }

    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--m245-root", required=True)
    ap.add_argument("--m17-root", required=True)
    ap.add_argument("--m18-root", required=True)
    ap.add_argument("--m19-root", required=True)
    ap.add_argument("--m20-root", required=True)
    ap.add_argument("--m21-root", required=True)
    ap.add_argument("--a8-records", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "schema": "s3.m21.all_window_stats.v1",
        "generated_at_utc": utc_now(),
        "m245_collector_windows": scan_m245(Path(args.m245_root)),
        "m17_vrp_entry_diff": scan_m17(Path(args.m17_root)),
        "run_level_roots": scan_run_level_roots({
            "m18_deep_analysis": Path(args.m18_root),
            "m19_roa_to_vrp": Path(args.m19_root),
            "m20_targeted_backfill": Path(args.m20_root),
            "m21_manifest_pp_alignment": Path(args.m21_root),
        }),
        "a8_candidate_subset": scan_a8(Path(args.a8_records)),
        "interpretation": {
            "important_denominator_note": (
                "M245 and M17 are window-level datasets, while M18-M21 are run-level or candidate-level datasets. "
                "A8 statistics should be reported as a candidate subset, not as full-window prevalence."
            ),
            "recommended_report_claim": (
                "Use M245/M17 for coverage and system observation scope; use M21/A8 for reverse-attribution evidence quality."
            ),
        },
    }

    json_path = out_dir / "m21_all_window_stats_summary.json"
    md_path = out_dir / "m21_all_window_stats_summary.md"

    json_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    m245 = summary["m245_collector_windows"]
    m17 = summary["m17_vrp_entry_diff"]
    a8 = summary["a8_candidate_subset"]

    md = []
    md.append("# M21 All-window and Candidate-subset Statistics")
    md.append("")
    md.append("## 1. Observation Coverage")
    md.append("")
    md.append(f"- M245 collector dir_count: `{m245.get('dir_count')}`")
    md.append(f"- M245 unique_window_count: `{m245.get('unique_window_count')}`")
    md.append(f"- M245 window_min_utc: `{m245.get('window_min_utc')}`")
    md.append(f"- M245 window_max_utc: `{m245.get('window_max_utc')}`")
    md.append(f"- M245 files_available: `{m245.get('files_available')}`")
    md.append("")
    md.append(f"- M17 dir_count: `{m17.get('dir_count')}`")
    md.append(f"- M17 unique_window_count: `{m17.get('unique_window_count')}`")
    md.append(f"- M17 window_min_utc: `{m17.get('window_min_utc')}`")
    md.append(f"- M17 window_max_utc: `{m17.get('window_max_utc')}`")
    md.append("")
    md.append("## 2. A8 Candidate Subset")
    md.append("")
    md.append(f"- A8 record_count: `{a8.get('record_count')}`")
    md.append(f"- TAL top20: `{a8.get('tal_top20')}`")
    md.append(f"- ASN top20: `{a8.get('asn_top20')}`")
    md.append(f"- manifestNumber top20: `{a8.get('manifestNumber_top20')}`")
    md.append(f"- window top20: `{a8.get('window_top20')}`")
    md.append(f"- notification relation top20: `{a8.get('notification_relation_top20')}`")
    md.append(f"- evidence completeness: `{a8.get('evidence_completeness')}`")
    md.append(f"- nearest_delta_sec: `{a8.get('nearest_delta_sec')}`")
    md.append("")
    md.append("## 3. M245 Notification-like Context")
    md.append("")
    md.append(f"- pp_status_top20: `{m245.get('pp_status_top20')}`")
    md.append(f"- notification_relation_top20: `{m245.get('notification_relation_top20')}`")
    md.append(f"- generic_relation_top20: `{m245.get('generic_relation_top20')}`")
    md.append("")
    md.append("## 4. Interpretation")
    md.append("")
    md.append("- M245/M17 should be used as window-level coverage statistics.")
    md.append("- A8 should be used as candidate-subset reverse-attribution evidence statistics.")
    md.append("- Do not report A8 candidate ratios as full-population prevalence.")
    md.append("- The current A8 result supports evidence-chain completeness, while strong causal attribution still requires live same-window capture.")
    md.append("")
    md_path.write_text("\n".join(md) + "\n", encoding="utf-8")

    check_path = out_dir / "M21_ALL_WINDOW_STATS_CHECK.txt"
    check_path.write_text(
        "\n".join([
            "M21_ALL_WINDOW_STATS=PASS",
            f"generated_at_utc = {summary['generated_at_utc']}",
            f"m245_unique_window_count = {m245.get('unique_window_count')}",
            f"m245_window_min_utc = {m245.get('window_min_utc')}",
            f"m245_window_max_utc = {m245.get('window_max_utc')}",
            f"m17_unique_window_count = {m17.get('unique_window_count')}",
            f"m17_window_min_utc = {m17.get('window_min_utc')}",
            f"m17_window_max_utc = {m17.get('window_max_utc')}",
            f"a8_record_count = {a8.get('record_count')}",
            f"summary_json = {json_path}",
            f"summary_md = {md_path}",
            "semantic_boundary = mixed_window_level_and_candidate_subset_statistics",
            "next_stage = M21_A8B_LIVE_SAME_WINDOW_CAPTURE",
            "",
        ]),
        encoding="utf-8",
    )

    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
