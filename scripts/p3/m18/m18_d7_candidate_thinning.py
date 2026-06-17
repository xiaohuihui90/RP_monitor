#!/usr/bin/env python3
import json
import argparse
from pathlib import Path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--high-priority-json", required=True)
    ap.add_argument("--top-n", type=int, default=1000)
    ap.add_argument("--top-small", type=int, default=200)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # 读取 high-priority candidate JSONL
    records = []
    with open(args.high_priority_json, "r", encoding="utf-8") as f:
        for line in f:
            records.append(json.loads(line))

    # 按 score 降序，抽取 top_n 和 top_small
    records_sorted = sorted(records, key=lambda x: x.get("m18_d6_score", 0), reverse=True)
    top_n = records_sorted[:args.top_n]
    top_small = records_sorted[:args.top_small]

    # 写入 JSONL
    top_n_file = out_dir / "M18_to_M19_seed_candidates_top1000.jsonl"
    top_small_file = out_dir / "M18_to_M19_seed_candidates_top200.jsonl"

    with open(top_n_file, "w", encoding="utf-8") as f:
        for r in top_n:
            f.write(json.dumps(r) + "\n")

    with open(top_small_file, "w", encoding="utf-8") as f:
        for r in top_small:
            f.write(json.dumps(r) + "\n")

    # 输出检查文件
    check_file = out_dir / "M18_D7_CANDIDATE_THINNING_CHECK.txt"
    check_file.write_text(f"M18_D7_CANDIDATE_THINNING=PASS\ninput_records={len(records)}\ntop_n={len(top_n)}\ntop_small={len(top_small)}\n")

    print("M18_D7_CANDIDATE_THINNING=PASS")
    print("input_records =", len(records))
    print("top_n =", len(top_n))
    print("top_small =", len(top_small))

if __name__ == "__main__":
    main()
