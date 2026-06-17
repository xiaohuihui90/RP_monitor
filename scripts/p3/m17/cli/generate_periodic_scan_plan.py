#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate M17 periodic scan plan without installing it.")
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--interval-minutes", type=int, default=5)
    args = ap.parse_args()

    repo = Path(args.repo_root).resolve()
    out = Path(args.out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)

    runner = out / "m17_periodic_scan.sh"
    cron = out / "m17_periodic_scan.cron.template"
    service = out / "m17-multilayer-scan.service.template"
    timer = out / "m17-multilayer-scan.timer.template"
    readme = out / "M17F_periodic_scan_plan.md"

    runner.write_text(f"""#!/usr/bin/env bash
set -euo pipefail

cd "{repo}"

source ~/.bashrc || true

if command -v conda >/dev/null 2>&1; then
  eval "$(conda shell.bash hook)" || true
  conda activate s3-radar || true
elif [ -f "$HOME/installers/ENTER/etc/profile.d/conda.sh" ]; then
  source "$HOME/installers/ENTER/etc/profile.d/conda.sh"
  conda activate s3-radar || true
fi

export PYTHONNOUSERSITE=1
export PYTHONPATH="$PWD:${{PYTHONPATH:-}}"

export M17_ROOT="$PWD/data/p3_collector/m17_anomalies"
export M17_SCAN_RUN_DIR="$PWD/data/p3_collector/e4a_joint_m17/m17_periodic_$(date -u +%Y%m%dT%H%M%SZ)"

mkdir -p "$M17_SCAN_RUN_DIR"/{{checks,outputs,logs,docs}}

export M17_LATEST_OBJECT_GROUP="$(
  find data/p3_collector/e4a_joint_snapshots/groups -maxdepth 1 -type d 2>/dev/null \\
    | sort \\
    | tail -n 1
)"

python scripts/p3/m17/cli/scan_multilayer_anomalies.py \\
  --collector-root data/p3_collector \\
  --out-root "$M17_ROOT" \\
  --run-dir "$M17_SCAN_RUN_DIR" \\
  --scan-advertised-view \\
  --scan-object-view \\
  --scan-validation-output \\
  --enable-temporal-skew-classifier \\
  --object-group-dir "$M17_LATEST_OBJECT_GROUP" \\
  --window-seconds 300 \\
  --strong-cycle-skew-seconds 120 \\
  --max-object-context-age-seconds 86400 \\
  --validator routinator \\
  --max-events 50 \\
  >> "$M17_SCAN_RUN_DIR/logs/m17_periodic_scan.log" 2>&1

python scripts/p3/m17/cli/compact_registry.py \\
  --out-root "$M17_ROOT" \\
  --summary-out "$M17_SCAN_RUN_DIR/outputs/M17_periodic_registry_compact_summary.json" \\
  >> "$M17_SCAN_RUN_DIR/logs/m17_periodic_scan.log" 2>&1
""", encoding="utf-8")

    runner.chmod(0o755)

    cron.write_text(f"""# M17 periodic scan cron template
# Review before installation. Do not install until M17-F acceptance is complete.
*/{args.interval_minutes} * * * * {runner} >> {repo}/data/p3_collector/m17_anomalies/logs/m17_periodic_cron.log 2>&1
""", encoding="utf-8")

    service.write_text(f"""[Unit]
Description=S3 M17 multilayer anomaly scan
After=network-online.target

[Service]
Type=oneshot
User=zhangxiaohui
WorkingDirectory={repo}
ExecStart={runner}
""", encoding="utf-8")

    timer.write_text(f"""[Unit]
Description=Run S3 M17 multilayer anomaly scan every {args.interval_minutes} minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec={args.interval_minutes}min
Persistent=true

[Install]
WantedBy=timers.target
""", encoding="utf-8")

    readme.write_text(f"""# M17-F Periodic Scan Plan

This directory contains templates only. They are not installed automatically.

Files:
- `m17_periodic_scan.sh`
- `m17_periodic_scan.cron.template`
- `m17-multilayer-scan.service.template`
- `m17-multilayer-scan.timer.template`

Recommended initial frequency:
- advertised_view scanner: every 5 minutes
- validation_output summary scanner: every 5 minutes
- object_view summary scanner: every 5-10 minutes, but object export itself should be scheduled separately or triggered by anomaly

Important:
- Do not confirm E4 from M17 output alone.
- M17 provides anomaly discovery and manual evidence location.
- M18/M19/M20/M21 provide deeper object diff, semantic diff, impact mapping, and E4 gate.
""", encoding="utf-8")

    print("M17_GENERATE_PERIODIC_SCAN_PLAN=DONE")
    print(f"runner = {runner}")
    print(f"cron_template = {cron}")
    print(f"service_template = {service}")
    print(f"timer_template = {timer}")
    print(f"readme = {readme}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
