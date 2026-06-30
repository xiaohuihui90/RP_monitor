# P10-D Batch ROV Impact Runner

P10-D batch-runs P10-C over multiple P8 PASS windows and merges the resulting
P10-A control-plane impact artifacts into paper-ready tables.

The chain is:

```text
P8 PASS windows -> P10-C per window -> P10-B routes.jsonl -> P10-A ROV impact -> merged batch tables
```

P10-D does not change P8, P9, P10-A, P10-B, or P10-C analysis semantics.

## Inputs

Main command:

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
  --out-dir data/probe/p10d_batch_rov_impact/p10d_latest6_routeviews2
```

Options:

- `--p8-root`: defaults to `data/probe/cross_probe_pipeline`.
- `--latest-n`: choose the latest N eligible P8 windows.
- `--start-window-id`, `--end-window-id`: optional inclusive window range.
- `--collector`: defaults to `routeviews2`.
- `--source`: `routeviews` or `ris`.
- `--rib-time-policy`: `nearest_leq`, `nearest`, or `nearest_geq`.
- `--download`: defaults to `true`; use `false` when RIBs are already local.
- `--bgpdump-bin`: path to `bgpdump`.
- `--max-routes`: optional smoke cap.
- `--continue-on-error`: defaults to `true`.
- `--skip-existing`: reuse an existing per-window P10-C run under the batch
  output directory when acceptance already exists.
- `--min-p8-skew-ok`: defaults to `true`; requires P8 status PASS and window
  quality OK, and honors P8 validator/skew checks when present.
- `--upload-minio`: accepted for future extension; current P10-D does not upload
  artifacts.

## P8 Window Selection

P10-D scans:

```text
<p8-root>/**/checks/P8_CROSS_PROBE_PIPELINE_ACCEPTANCE.txt
```

Eligible windows must have:

- `P8_CROSS_PROBE_PIPELINE=PASS`
- `window_quality=OK`
- `all_validator_healthy=true`, when the field is present
- `capture_time_skew_within_threshold=true`, when the field is present
- parseable `window_id=win_YYYYMMDDTHHMMSSZ_1h`

Windows are sorted by `window_id` time, then filtered by optional range and
`--latest-n`.

## Per-Window Behavior

For each selected window, P10-D invokes P10-C:

```text
scripts/runtime/run_p10c_time_aligned_rov_once.sh
```

Per-window P10-C outputs are stored under:

```text
<out-dir>/p10c_runs/<window_id>_<collector>/
```

If one window fails, P10-D records the failure in `p10d_window_summary.csv` and
continues when `--continue-on-error true`.

If a local RIB is corrupt, P10-C fails before P10-B/P10-A run. P10-D records
that window as failed and continues to later windows.

## Outputs

Output directory:

```text
data/probe/p10d_batch_rov_impact/<run_id>/
```

Files:

- `p10d_window_summary.csv`
- `p10d_transition_matrix_merged.csv`
- `p10d_affected_prefix_merged.csv`
- `p10d_affected_origin_as_merged.csv`
- `p10d_transition_event_sample.jsonl`
- `p10d_batch_summary.json`
- `checks/P10D_BATCH_ROV_IMPACT_ACCEPTANCE.txt`

`p10d_window_summary.csv` contains one row per selected P8 window:

```text
batch_id,window_id,p8_run_dir,p10c_run_dir,p10a_run_dir,p10b_run_dir,
collector,selected_rib_time_utc,rib_time_delta_sec,p10c_status,p10a_status,
p10b_status,route_count,transition_event_count,affected_prefix_count,
affected_origin_as_count,usable_window,normal_impact_analysis_executed,
exclusion_reasons
```

`p10d_transition_matrix_merged.csv` merges all P10-A `transition_matrix.csv`
files and adds:

```text
batch_id,window_id,collector,p10a_run_dir
```

`p10d_affected_prefix_merged.csv` merges all P10-A
`affected_prefix_summary.csv` files and adds:

```text
batch_id,collector,p10a_run_dir
```

`p10d_affected_origin_as_merged.csv` merges all P10-A
`affected_origin_as_summary.csv` files and adds:

```text
batch_id,collector,p10a_run_dir
```

`p10d_transition_event_sample.jsonl` copies the first N P10-A transition events
across the batch. The default N is 10000 and the original P10-A schema is kept.

## Batch Summary

`p10d_batch_summary.json` includes:

- requested, selected, succeeded, excluded, and failed window counts;
- total route count;
- total transition event count;
- unique affected prefix and origin AS counts;
- transition type distribution;
- top affected origin ASes;
- top affected prefixes;
- collector and max-routes metadata.

## Status Semantics

`PASS`:

- at least one window completed P10-C/P10-A normally;
- merged outputs are present;
- no selected window failed or was excluded.

`PASS_WITH_EXCLUSIONS`:

- batch completed;
- at least one window produced useful output or an expected exclusion;
- some windows were excluded by route-time quality gates, input quality, or
  local RIB problems.

`FAIL`:

- no eligible P8 PASS windows were found;
- no usable P10-C/P10-A result exists;
- or key merged outputs are missing.

P10-D never claims real data-plane loss, real route filtering, or confirmed root
cause. Security relevance remains `potential` in P10-A transition events.

## Validation

```bash
python -m py_compile probe/rov/*.py
bash -n scripts/runtime/run_p10d_batch_rov_impact_once.sh
```

Dry run over the latest six P8 windows:

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
  --out-dir data/probe/p10d_batch_rov_impact/p10d_latest6_routeviews2

cat data/probe/p10d_batch_rov_impact/p10d_latest6_routeviews2/checks/P10D_BATCH_ROV_IMPACT_ACCEPTANCE.txt
head -n 5 data/probe/p10d_batch_rov_impact/p10d_latest6_routeviews2/p10d_window_summary.csv
```

Do not commit `data/`, `logs/`, downloaded RIB files, route-table outputs, or
per-window P10 run outputs.
