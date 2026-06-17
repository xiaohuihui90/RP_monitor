#!/usr/bin/env bash
set -u

PROJECT_DIR="$HOME/s3_stage3_v3_code"
MARK_BEGIN="# M23B_F_BEGIN"
MARK_END="# M23B_F_END"

M21_RUN_DIR="data/p3_collector/m21_manifest_pp_alignment/history/m21_a1_roa_repository_listing_20260607T144706Z"
M23B_OUT="$M21_RUN_DIR/outputs/m23b_five_tal_candidate_aware_live_capture"
M23B_D_OUT="$M23B_OUT/m23b_d_high_impact_same_window_capture"
M23B_F_OUT="$M23B_OUT/m23b_f_longitudinal_scheduler"
M22G_OUT="data/p3_collector/m21_manifest_pp_alignment/history/m21_a1_roa_repository_listing_20260607T144706Z/outputs/m22g_roa_repository_cluster_stats_for_mapped_tal_sample"
PAPER_TABLE_OUT="data/p3_collector/m21_manifest_pp_alignment/history/m21_a1_roa_repository_listing_20260607T144706Z/outputs/paper_ready_tables"

TMP_CRON="$(mktemp)"
crontab -l 2>/dev/null | sed "/$MARK_BEGIN/,/$MARK_END/d" > "$TMP_CRON" || true

cat >> "$TMP_CRON" <<EOF
$MARK_BEGIN
# M23B-F hourly 40-target lightweight census, CD2 node
10 * * * * /bin/bash -lc 'cd $PROJECT_DIR && bash scripts/p3/m23b/f/run_m23b_f1_hourly_census_once.sh >> $M23B_F_OUT/logs/hourly_census/cron.log 2>&1'

# M23B-F high-impact 14-target capture, CD2 node
20,50 * * * * /bin/bash -lc 'cd $PROJECT_DIR && bash scripts/p3/m23b/f/run_m23b_f2_high_impact_capture_once.sh >> $M23B_F_OUT/logs/high_impact_capture/cron.log 2>&1'

# M23B-F daily summary, UTC daily
10 0 * * * /bin/bash -lc 'cd $PROJECT_DIR && source ~/.bashrc >/dev/null 2>&1 || true && conda activate s3-radar >/dev/null 2>&1 || true && export PYTHONNOUSERSITE=1 && export PYTHONPATH=$PROJECT_DIR:${PYTHONPATH:-} && export M21_RUN_DIR=$M21_RUN_DIR && export M23B_OUT=$M23B_OUT && export M23B_D_OUT=$M23B_D_OUT && export M23B_F_OUT=$M23B_F_OUT && python scripts/p3/m23b/f/run_m23b_f3_daily_aggregator.py --m23b-f-out "$M23B_F_OUT" --m23b-d-out "$M23B_D_OUT" --date "$(date -u +%F)" >> "$M23B_F_OUT/logs/daily_summary/cron.log" 2>&1'

# M23B-F paper tables, UTC daily
20 0 * * * /bin/bash -lc 'cd $PROJECT_DIR && source ~/.bashrc >/dev/null 2>&1 || true && conda activate s3-radar >/dev/null 2>&1 || true && export PYTHONNOUSERSITE=1 && export PYTHONPATH=$PROJECT_DIR:${PYTHONPATH:-} && export M21_RUN_DIR=$M21_RUN_DIR && export M23B_OUT=$M23B_OUT && export M23B_D_OUT=$M23B_D_OUT && export M23B_F_OUT=$M23B_F_OUT && export M22G_OUT=$M22G_OUT && export PAPER_TABLE_OUT=$PAPER_TABLE_OUT && python scripts/p3/m23b/f/run_m23b_f4_generate_paper_tables.py --m23b-f-out "$M23B_F_OUT" --m23b-d-out "$M23B_D_OUT" --out-dir "$M23B_F_OUT/paper_tables/latest" >> "$M23B_F_OUT/logs/paper_tables/cron.log" 2>&1'
$MARK_END
EOF

crontab "$TMP_CRON"
rm -f "$TMP_CRON"

mkdir -p "$M23B_F_OUT/checks"

{
  echo "M23B_F5_CRON_INSTALL=PASS"
  echo "installed_at_utc = $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "node = CD2"
  echo "M22G_OUT = $M22G_OUT"
  echo "PAPER_TABLE_OUT = $PAPER_TABLE_OUT"
  echo "cron_schedule = hourly_census:10min, high_impact_capture:20/50min, daily_summary:00:10UTC, paper_tables:00:20UTC"
  echo "semantic_boundary = scheduler_installation_not_measurement"
  echo "next_stage = M23B_F6_HEALTH_CHECK_AFTER_24H"
  echo
} > "$M23B_F_OUT/checks/M23B_F5_CRON_INSTALL_CHECK.txt"

cat "$M23B_F_OUT/checks/M23B_F5_CRON_INSTALL_CHECK.txt"
echo
echo "========== CRONTAB =========="
crontab -l | sed -n "/$MARK_BEGIN/,/$MARK_END/p"
