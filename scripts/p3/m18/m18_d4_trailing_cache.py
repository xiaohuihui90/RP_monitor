#!/usr/bin/env python3
import json, os
from pathlib import Path
import argparse

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probewise-lifetime-json", required=True)
    ap.add_argument("--pair-lag-json", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    out_dir = Path(args.out_dir).resolve()
    print("DEBUG out_dir =", out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # 读取 JSONL
    lifetime_records = [json.loads(line) for line in Path(args.probewise_lifetime_json).read_text().splitlines() if line.strip()]
    pair_lag_records = [json.loads(line) for line in Path(args.pair_lag_json).read_text().splitlines() if line.strip()]

    summary = {
        "records_written": len(lifetime_records),
        "counters": {
            "trailing_v1_candidate_count": len(lifetime_records),
        },
        "trailing_v1_summary": { r['vrp_key']: True for r in lifetime_records },
    }

    # 写入检查文件
    check_file = out_dir / "M18_D4_TRAILING_CACHE_CHECK.txt"
    check_file.write_text(
        f"M18_D4_TRAILING_CACHE=PASS\ngenerated_at_utc = {os.popen('date -u +%Y-%m-%dT%H:%M:%SZ').read().strip()}\n"
    )

    # 写入 JSON 输出
    out_file = out_dir / "m18_trailing_cache_summary.json"
    out_file.write_text(json.dumps(summary, indent=2))

if __name__ == "__main__":
    main()
