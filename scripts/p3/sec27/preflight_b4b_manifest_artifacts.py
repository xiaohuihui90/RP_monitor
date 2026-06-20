#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path


ARTIFACT_LIST = Path("data/p3_analysis/sec27/b4b_manifest_filelist_preflight/b4b_candidate_artifacts.txt")
OUT_DIR = Path("data/p3_analysis/sec27/b4b_manifest_filelist_preflight")
REPORT = Path("data/p3_analysis/sec27/reports/sec27_b4b_manifest_filelist_preflight_report.json")
SUMMARY_CSV = Path("paper_tables/latest/sec27_b4b/table_b4b_artifact_profile_summary.csv")


def classify(path: Path) -> str:
    s = str(path).lower()
    name = path.name.lower()

    if "m22b" in s:
        return "M22B_MANIFEST_FILELIST"
    if "m22c" in s:
        return "M22C_HASH_VERIFY"
    if "m22d" in s:
        return "M22D_EVIDENCE_CLASSIFICATION"
    if "m22" in s:
        return "M22_OTHER"
    if "manifest" in name and "filelist" in name:
        return "MANIFEST_FILELIST"
    if "filelist" in name:
        return "FILELIST"
    if "hash" in name and ("verify" in name or "match" in name):
        return "HASH_VERIFY_OR_MATCH"
    if "roa" in name and "manifest" in name:
        return "ROA_MANIFEST"
    if "active_manifest_records" in name:
        return "ACTIVE_MANIFEST_RECORDS"
    if "mft" in name or name.endswith(".mft"):
        return "MFT_OR_WRAPPER"
    if "manifest" in name:
        return "MANIFEST_OTHER"
    return "OTHER"


def safe_read_text(path: Path, max_bytes: int = 20000) -> str:
    try:
        with path.open("rb") as f:
            data = f.read(max_bytes)
        return data.decode("utf-8", errors="replace")
    except Exception as e:
        return f"<READ_ERROR {e}>"


def profile_file(path: Path) -> dict:
    text = safe_read_text(path)
    lines = [x for x in text.splitlines() if x.strip()]
    sample = {
        "path": str(path),
        "class": classify(path),
        "size_bytes": path.stat().st_size if path.exists() else None,
        "suffix": path.suffix,
        "line_count_sample": len(lines),
        "format_guess": "unknown",
        "keys": [],
        "header": [],
        "sample_lines": lines[:3],
    }

    if not lines:
        sample["format_guess"] = "empty_or_binary"
        return sample

    first = lines[0].strip()

    if first.startswith("{"):
        sample["format_guess"] = "json_or_jsonl"
        try:
            obj = json.loads(first)
            if isinstance(obj, dict):
                sample["keys"] = sorted(obj.keys())[:80]
        except Exception:
            pass
        return sample

    if first.startswith("["):
        sample["format_guess"] = "json_array_or_text"
        try:
            obj = json.loads(text)
            if isinstance(obj, list) and obj and isinstance(obj[0], dict):
                sample["keys"] = sorted(obj[0].keys())[:80]
        except Exception:
            pass
        return sample

    if "," in first:
        sample["format_guess"] = "csv_or_text"
        try:
            sample["header"] = next(csv.reader([first]))
        except Exception:
            pass
        return sample

    sample["format_guess"] = "text_or_binary"
    return sample


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    SUMMARY_CSV.parent.mkdir(parents=True, exist_ok=True)

    paths = []
    if ARTIFACT_LIST.exists():
        for line in ARTIFACT_LIST.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line:
                p = Path(line)
                if p.exists():
                    paths.append(p)

    by_type = Counter(classify(p) for p in paths)

    # 每类最多 profile 10 个，避免输出过大
    samples = []
    per_type = defaultdict(int)
    for p in paths:
        t = classify(p)
        if per_type[t] >= 10:
            continue
        samples.append(profile_file(p))
        per_type[t] += 1

    profile_path = OUT_DIR / "b4b_artifact_profile_samples.json"
    profile_path.write_text(json.dumps(samples, indent=2, ensure_ascii=False), encoding="utf-8")

    with SUMMARY_CSV.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["section", "value", "count"])
        w.writerow(["overall", "artifact_count", len(paths)])
        for k, v in by_type.most_common():
            w.writerow(["artifact_type", k, v])

    report = {
        "schema": "sec27.b4b_manifest_filelist_preflight_report.v1",
        "status": "PASS" if paths else "FAIL_NO_ARTIFACTS",
        "artifact_list": str(ARTIFACT_LIST),
        "artifact_count": len(paths),
        "by_type": dict(by_type),
        "profile_samples": str(profile_path),
        "summary_csv": str(SUMMARY_CSV),
        "samples_by_type": {
            t: [str(p) for p in paths if classify(p) == t][:20]
            for t in sorted(by_type)
        },
        "interpretation": [
            "This preflight identifies available manifest/fileList/hash artifacts for B4B.",
            "It does not yet join L2-b source_uri to manifest fileList.",
            "B4B builder should be written only after choosing the concrete artifact schema.",
        ],
    }

    REPORT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print("status =", report["status"])
    print("artifact_count =", report["artifact_count"])
    print("by_type =", report["by_type"])
    print("WROTE", REPORT)
    print("WROTE", SUMMARY_CSV)
    print("WROTE", profile_path)


if __name__ == "__main__":
    main()
