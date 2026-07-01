# P10-D2 / P11A Window-Bound VRP Replay

P10-D2 fixes the historical replay problem where P10-C/P10-D used mutable
`latest_*` VRP files for old P8 windows. For each P8 PASS window, it archives
the exact VRP inputs that participated in that P8 observation and lets P10-C and
P10-D replay with those window-bound inputs.

This avoids false exclusions such as:

- `P8_INPUT_METADATA_MISMATCH`
- `PARTIAL_TAL_VIEW`
- `VRP_COUNT_RATIO_LOW`
- `VRP_SKEW_TOO_LARGE`

when the only problem was that current `latest_*` files no longer matched the
historical P8 window.

## Integrated Stable Input Capture In P8

The CD2 P8 runner now captures stable input copies before P2 runs:

```bash
scripts/runtime/run_cd2_cross_probe_archive_once.sh
```

Default environment switches:

```bash
export P8_STABLE_INPUTS=1
export P8_INPUT_VRP_ARCHIVE=1
export P8_INPUT_VRP_UPLOAD=0
export P8_INPUT_VRP_ARCHIVE_REQUIRED=0
```

For each P8 run, the runner first copies the mutable `latest_*` inputs into:

```text
data/probe/cross_probe_pipeline/<run_id>/input_vrps/
  probe_id=probe-cd/latest_metadata.json
  probe_id=probe-cd/latest_normalized_vrp.jsonl
  probe_id=probe-sg/latest_metadata.json
  probe_id=probe-sg/latest_normalized_vrp.jsonl
  probe_id=probe-k02/latest_metadata.json
  probe_id=probe-k02/latest_normalized_vrp.jsonl
```

P2/P3/P4/P6 then use these stable copies instead of direct `latest_*` paths.
After P2 writes `cross_probe_summary.json`, the runner calls the P8 input VRP
archive in `stable_copy` mode and writes:

```text
data/probe/p8_input_vrps/window_id=<window_id>/p8_input_vrp_manifest.json
```

The P8 acceptance file records:

```text
stable_input_materialized=true
p2_used_stable_inputs=true
p8_input_vrp_archive_status=PASS
p8_input_metadata_consistent=true
p8_input_archive_from_stable_copy=true
```

This removes the race where an independent archive command read a newer
`latest_*` file after the hourly probe cron had already overwritten it.

## Archive A P8 Window Input

```bash
bash scripts/runtime/run_p8_input_vrp_archive_once.sh \
  --p8-run-dir data/probe/cross_probe_pipeline/<P8_PASS_RUN> \
  --out-dir data/probe/p8_input_vrps \
  --upload-minio false \
  --compress gzip
```

The archive script reads:

```text
<p8-run-dir>/checks/P8_CROSS_PROBE_PIPELINE_ACCEPTANCE.txt
```

It only archives windows with:

```text
P8_CROSS_PROBE_PIPELINE=PASS
window_quality=OK
```

Default input paths:

```text
probe-cd  data/probe/live_vrp_snapshots/probe-cd/latest_metadata.json
probe-cd  data/probe/live_vrp_snapshots/probe-cd/latest_normalized_vrp.jsonl

probe-sg  data/probe/remote_snapshots/probe-sg/latest_metadata.json
probe-sg  data/probe/remote_snapshots/probe-sg/latest_normalized_vrp.jsonl

probe-k02 data/probe/remote_snapshots/probe-k02/latest_metadata.json
probe-k02 data/probe/remote_snapshots/probe-k02/latest_normalized_vrp.jsonl
```

Output layout:

```text
data/probe/p8_input_vrps/window_id=<window_id>/
  p8_input_vrp_manifest.json
  checks/P8_INPUT_VRP_ARCHIVE_ACCEPTANCE.txt
  probe_id=probe-cd/
    latest_metadata.json
    latest_normalized_vrp.jsonl.gz
    sha256sums.txt
  probe_id=probe-sg/
    latest_metadata.json
    latest_normalized_vrp.jsonl.gz
    sha256sums.txt
  probe_id=probe-k02/
    latest_metadata.json
    latest_normalized_vrp.jsonl.gz
    sha256sums.txt
```

Acceptance:

```bash
cat data/probe/p8_input_vrps/window_id=<window_id>/checks/P8_INPUT_VRP_ARCHIVE_ACCEPTANCE.txt
```

Expected:

```text
P8_INPUT_VRP_ARCHIVE=PASS
window_id=<window_id>
probe_count=3
uploaded=false
minio_stat_ok=false
```

If a source VRP or metadata file is missing, the archive status is `FAIL`. If
the current metadata does not match P8 summary fields when those fields are
available, the archive status is `PASS_WITH_EXCLUSIONS` rather than silently
claiming success.

For compatibility, the standalone archive command still defaults to
`--source-mode latest`. To archive from stable copies explicitly:

```bash
bash scripts/runtime/run_p8_input_vrp_archive_once.sh \
  --p8-run-dir data/probe/cross_probe_pipeline/<P8_RUN> \
  --out-dir data/probe/p8_input_vrps \
  --source-mode stable_copy \
  --input-root data/probe/cross_probe_pipeline/<P8_RUN>/input_vrps \
  --upload-minio false
```

## Optional MinIO Upload

Use explicit upload only:

```bash
bash scripts/runtime/run_p8_input_vrp_archive_once.sh \
  --p8-run-dir data/probe/cross_probe_pipeline/<P8_PASS_RUN> \
  --out-dir data/probe/p8_input_vrps \
  --upload-minio true \
  --minio-prefix "$MINIO_PREFIX" \
  --mc-bin mc
```

Remote layout:

```text
MINIO_PREFIX/p8_input_vrps/window_id=<window_id>/p8_input_vrp_manifest.json
MINIO_PREFIX/p8_input_vrps/window_id=<window_id>/probe_id=<probe>/latest_metadata.json
MINIO_PREFIX/p8_input_vrps/window_id=<window_id>/probe_id=<probe>/latest_normalized_vrp.jsonl.gz
MINIO_PREFIX/p8_input_vrps/window_id=<window_id>/probe_id=<probe>/sha256sums.txt
```

The script runs `mc stat` after upload.

## P10-C Window-Bound Replay

P10-C now supports:

```text
--vrp-input-mode latest|window_bound
--p8-input-vrp-manifest PATH
```

Example:

```bash
bash scripts/runtime/run_p10c_time_aligned_rov_once.sh \
  --p8-run-dir data/probe/cross_probe_pipeline/<P8_PASS_RUN> \
  --collector routeviews2 \
  --source routeviews \
  --rib-time-policy nearest_leq \
  --download false \
  --bgpdump-bin "$(command -v bgpdump)" \
  --max-routes 100000 \
  --vrp-input-mode window_bound \
  --p8-input-vrp-manifest data/probe/p8_input_vrps/window_id=<window_id>/p8_input_vrp_manifest.json \
  --out-dir data/probe/p10c_time_aligned_rov/<window_id>_routeviews2_window_bound
```

When the manifest contains `.jsonl.gz` VRPs, P10-C decompresses them into:

```text
<p10c-run-dir>/input_vrps/probe_id=<probe>/latest_normalized_vrp.jsonl
```

and passes those paths to P10-A. P10-A writes them into
`p10_input_manifest.json`.

Expected behavior:

- `p8_input_metadata_match=true` when P8 summary has comparable snapshot/capture
  data and the archive was made from the same P8 inputs.
- `normal_impact_analysis_executed=true` when only the old mutable-latest issue
  was causing exclusions.
- If route time is too far from the selected RIB, P10-A may still return
  `PASS_WITH_EXCLUSIONS`; that is a separate route-time quality gate.

## P10-D Historical Batch Replay

P10-D now supports:

```text
--vrp-input-mode latest|window_bound
--p8-input-vrp-root data/probe/p8_input_vrps
--require-window-bound-vrp true|false
```

Recommended historical replay:

```bash
bash scripts/runtime/run_p10d_batch_rov_impact_once.sh \
  --p8-root data/probe/cross_probe_pipeline \
  --latest-n 6 \
  --collector routeviews2 \
  --source routeviews \
  --rib-time-policy nearest_leq \
  --download false \
  --bgpdump-bin "$(command -v bgpdump)" \
  --max-routes 100000 \
  --vrp-input-mode window_bound \
  --p8-input-vrp-root data/probe/p8_input_vrps \
  --require-window-bound-vrp true \
  --out-dir data/probe/p10d_batch_rov_impact/p10d_latest6_routeviews2_window_bound
```

For each window, P10-D looks for:

```text
data/probe/p8_input_vrps/window_id=<window_id>/p8_input_vrp_manifest.json
```

If the manifest is missing, the window is skipped with:

```text
skip_reason=NO_WINDOW_BOUND_VRP_INPUT
```

P10-D does not fall back to current `latest_*` files in `window_bound` mode.

`p10d_window_summary.csv` includes:

```text
vrp_input_mode,p8_input_vrp_manifest,window_bound_vrp_available,skip_reason
```

## Validation

```bash
python -m py_compile probe/archive_p8_input_vrps.py probe/rov/*.py
bash -n scripts/runtime/run_p8_input_vrp_archive_once.sh
bash -n scripts/runtime/run_p10c_time_aligned_rov_once.sh
bash -n scripts/runtime/run_p10d_batch_rov_impact_once.sh
```

Window-bound smoke:

```bash
bash scripts/runtime/run_p8_input_vrp_archive_once.sh \
  --p8-run-dir data/probe/cross_probe_pipeline/<P8_PASS_RUN> \
  --out-dir data/probe/p8_input_vrps \
  --upload-minio false

bash scripts/runtime/run_p10d_batch_rov_impact_once.sh \
  --p8-root data/probe/cross_probe_pipeline \
  --start-window-id <window_id> \
  --end-window-id <window_id> \
  --collector routeviews2 \
  --source routeviews \
  --rib-time-policy nearest_leq \
  --download false \
  --bgpdump-bin "$(command -v bgpdump)" \
  --max-routes 100000 \
  --vrp-input-mode window_bound \
  --p8-input-vrp-root data/probe/p8_input_vrps \
  --out-dir data/probe/p10d_batch_rov_impact/<window_id>_window_bound_smoke
```

Then inspect:

```bash
cat data/probe/p10d_batch_rov_impact/<window_id>_window_bound_smoke/p10d_window_summary.csv
cat data/probe/p10d_batch_rov_impact/<window_id>_window_bound_smoke/checks/P10D_BATCH_ROV_IMPACT_ACCEPTANCE.txt
```

The replay should no longer be excluded solely because old P8 windows were
compared against current mutable `latest_*` VRPs.

Do not commit `data/`, `logs/`, RIB files, archived full VRPs, or generated P10
run outputs.
