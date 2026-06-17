#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from s3lib.p0.jsonio import write_json
from s3lib.p0.paths import P0Paths, ensure_p0_dirs
from s3lib.p0.scanner import scan_window_dirs
from s3lib.p0.timeutil import utc_now


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--history-root",
        default="data/p3_collector/m245_three_layer_baseline/history",
    )
    parser.add_argument(
        "--out-dir",
        default="data/p3_collector/m245_three_layer_baseline/p0_acceptance",
    )
    args = parser.parse_args()

    history_root = Path(args.history_root)
    out_dir = Path(args.out_dir)

    paths = P0Paths.from_defaults()
    ensure_p0_dirs(paths)

    required_dirs = [
        Path("scripts/p3"),
        Path("s3lib/p0"),
        paths.history_root,
        paths.reports_dir,
        paths.acceptance_dir,
        paths.evidence_pack_root,
        paths.m17_input_dir,
    ]

    required_files = [
        Path("s3lib/p0/__init__.py"),
        Path("s3lib/p0/jsonio.py"),
        Path("s3lib/p0/timeutil.py"),
        Path("s3lib/p0/paths.py"),
        Path("s3lib/p0/scanner.py"),
    ]

    window_dirs = scan_window_dirs(history_root)

    missing_dirs = [str(p) for p in required_dirs if not p.exists()]
    missing_files = [str(p) for p in required_files if not p.exists()]

    status = "PASS" if not missing_dirs and not missing_files and len(window_dirs) > 0 else "FAIL"

    summary = {
        "schema": "s3.p0.batch1_init_check.v1",
        "generated_at_utc": utc_now(),
        "status": status,
        "history_root": str(history_root),
        "out_dir": str(out_dir),
        "window_count": len(window_dirs),
        "recent_windows": [str(p) for p in window_dirs[-10:]],
        "missing_dirs": missing_dirs,
        "missing_files": missing_files,
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "p0_batch1_init_check.json", summary)

    txt_lines = [
        f"P0_BATCH1_INIT_CHECK={status}",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"history_root = {summary['history_root']}",
        f"window_count = {summary['window_count']}",
        f"missing_dirs = {len(missing_dirs)}",
        f"missing_files = {len(missing_files)}",
    ]

    (out_dir / "p0_batch1_init_check.txt").write_text("\n".join(txt_lines) + "\n", encoding="utf-8")
    print("\n".join(txt_lines))


if __name__ == "__main__":
    main()
