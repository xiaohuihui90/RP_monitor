# P9 Runtime Retention And MinIO Checkpoint

P9 manages the storage pressure created by hourly probe and cross-probe runs.
It is intentionally separate from P1-P8 and does not change their behavior.

P9 has three small tools:

```text
probe/build_p8_rollup.py
probe/manage_runtime_retention.py
probe/archive_snapshot_checkpoint.py
```

and one runtime wrapper:

```text
scripts/runtime/run_runtime_retention_once.sh
```

## What P9 Does

1. Build a P8 rollup from `data/probe/cross_probe_pipeline`.
2. Optionally upload that small rollup to MinIO under:

   ```text
   MINIO_PREFIX/rollups/<rollup_id>/
   ```

3. Prune old local P8 runs while keeping recent runs and retaining failures by
   default.
4. Prune old per-probe runtime data:

   ```text
   data/probe/live_vrp_snapshots/<probe_id>/history/
   data/probe/e2e_msal_cycles/<probe_id>/
   ```

5. Optionally checkpoint `latest_normalized_vrp.jsonl`, but only when
   `--checkpoint` is explicitly enabled.

## MinIO Boundary

P9 uses only the `mc` CLI. It does not use boto3 and does not read, print, or
write access keys or secret keys.

Required environment for upload:

```bash
export MINIO_ALIAS=rp-monitor
export MINIO_BUCKET=rpki-probe-artifacts
export MINIO_PREFIX=rp-monitor
```

The alias must already be configured for `mc`, for example outside P9:

```bash
mc alias set rp-monitor http://127.0.0.1:9000 "$MINIO_ACCESS_KEY" "$MINIO_SECRET_KEY"
```

Do not put credentials in cron lines, reports, or logs.

## P8 Rollup

Dry-run rollup:

```bash
python probe/build_p8_rollup.py \
  --p8-root data/probe/cross_probe_pipeline \
  --out-dir data/probe/runtime_retention/manual_rollup \
  --limit 24
```

Upload rollup and verify with `mc stat`:

```bash
python probe/build_p8_rollup.py \
  --p8-root data/probe/cross_probe_pipeline \
  --out-dir data/probe/runtime_retention/manual_rollup_upload \
  --limit 24 \
  --upload-minio
```

Outputs:

```text
p8_rollup.jsonl
p8_rollup_summary.json
```

## Runtime Retention

Default retention:

- keep newest 12 P8 runs;
- keep newest 6 snapshot history directories per probe;
- keep newest 24 E2 cycle directories per probe;
- dry-run unless `--apply` is used.

Dry-run:

```bash
python probe/manage_runtime_retention.py \
  --probe-id probe-cd \
  --p8-root data/probe/cross_probe_pipeline \
  --snapshot-root data/probe/live_vrp_snapshots \
  --cycle-root data/probe/e2e_msal_cycles \
  --out-dir data/probe/runtime_retention/probe-cd/manual_retention \
  --p8-rollup-summary data/probe/runtime_retention/manual_rollup/p8_rollup_summary.json
```

Apply:

```bash
python probe/manage_runtime_retention.py \
  --probe-id probe-cd \
  --out-dir data/probe/runtime_retention/probe-cd/apply_retention \
  --apply
```

P8 cleanup policy:

- old P8 runs are deletable only if P8, P6, and P7 all have `PASS`;
- `FAIL` and `WINDOW_INCOMPLETE` runs are retained by default;
- failed runs are deleted only with explicit `--delete-failed-before-days N`.

Acceptance:

```text
checks/P9_RUNTIME_RETENTION_ACCEPTANCE.txt
```

`P9_RUNTIME_RETENTION=PASS` requires:

- `report_json_ok=true`
- `rollup_uploaded_if_requested=true`
- `minio_stat_ok_if_uploaded=true`
- `deleted_only_verified_pass_runs=true`
- `keep_recent_runs_respected=true`
- `no_large_snapshot_upload_without_explicit_allow=true`

## Snapshot Checkpoint

Snapshot checkpoint is off by default. This command is a no-op unless
`--checkpoint` is present.

Build gzip checkpoint locally:

```bash
python probe/archive_snapshot_checkpoint.py \
  --probe-id probe-cd \
  --snapshot-root data/probe/live_vrp_snapshots \
  --out-dir data/probe/runtime_retention/probe-cd/checkpoint \
  --checkpoint \
  --gzip
```

Upload checkpoint to MinIO:

```bash
python probe/archive_snapshot_checkpoint.py \
  --probe-id probe-cd \
  --snapshot-root data/probe/live_vrp_snapshots \
  --out-dir data/probe/runtime_retention/probe-cd/checkpoint_upload \
  --checkpoint \
  --gzip \
  --upload-minio \
  --allow-large-snapshot-upload
```

Object key prefix:

```text
MINIO_PREFIX/snapshot_checkpoints/probe_id=<probe>/date=<YYYY-MM-DD>/
```

Without `--allow-large-snapshot-upload`, P9 refuses to upload the normalized VRP
checkpoint even if `--upload-minio` is present.

Outputs:

```text
checkpoint_manifest.json
checkpoint_archive_report.json
checks/P9_SNAPSHOT_CHECKPOINT_ACCEPTANCE.txt
```

`--snapshot-root` may point either to the snapshot root parent or directly to a
single probe directory. Both forms are valid:

```text
data/probe/live_vrp_snapshots
data/probe/live_vrp_snapshots/probe-cd
data/probe/remote_snapshots/probe-sg
```

When checkpoint inputs are missing for one probe, P9 writes that probe's
`P9_SNAPSHOT_CHECKPOINT_ACCEPTANCE.txt` with `P9_SNAPSHOT_CHECKPOINT=SKIPPED`,
writes `checkpoint_archive_report.json`, and continues with the remaining
probes.

## Runtime Wrapper

Default wrapper behavior:

- builds P8 rollup;
- uploads rollup to MinIO by default (`P9_UPLOAD_MINIO=1`);
- runs local retention in dry-run mode;
- does not checkpoint latest normalized VRP unless `P9_CHECKPOINT=1`.

Dry-run, no MinIO upload:

```bash
P9_UPLOAD_MINIO=0 bash scripts/runtime/run_runtime_retention_once.sh
```

Continuous testing upload of P8 rollups:

```bash
export MINIO_ALIAS=rp-monitor
export MINIO_BUCKET=rpki-probe-artifacts
export MINIO_PREFIX=rp-monitor
bash scripts/runtime/run_runtime_retention_once.sh
```

Enable snapshot checkpoint upload explicitly:

```bash
export MINIO_ALIAS=rp-monitor
export MINIO_BUCKET=rpki-probe-artifacts
export MINIO_PREFIX=rp-monitor
P9_CHECKPOINT=1 \
P9_ALLOW_LARGE_SNAPSHOT_UPLOAD=1 \
bash scripts/runtime/run_runtime_retention_once.sh
```

CD2 mixed local/remote checkpoint roots can be passed explicitly:

```bash
P9_PROBE_IDS=probe-cd,probe-sg,probe-k02 \
P9_CHECKPOINT=1 \
P9_UPLOAD_MINIO=0 \
P9_SNAPSHOT_ROOT_MAP=probe-cd=data/probe/live_vrp_snapshots/probe-cd,probe-sg=data/probe/remote_snapshots/probe-sg,probe-k02=data/probe/remote_snapshots/probe-k02 \
bash scripts/runtime/run_runtime_retention_once.sh
```

Without `P9_SNAPSHOT_ROOT_MAP`, the wrapper uses CD2 defaults:

- `probe-cd` -> `data/probe/live_vrp_snapshots/probe-cd`
- `probe-sg` -> `data/probe/remote_snapshots/probe-sg`
- `probe-k02` -> `data/probe/remote_snapshots/probe-k02`

`retention_report.json` reports:

- `checkpoint_report_count`: successful `PASS` checkpoint probes;
- `checkpoint_report_skipped_count`: probes skipped because inputs were missing;
- `checkpoint_report_failed_count`: checkpoint probes that failed for reasons other than skip.

Apply local deletion:

```bash
P9_UPLOAD_MINIO=0 P9_APPLY=1 bash scripts/runtime/run_runtime_retention_once.sh
```

## CD2 Example

```bash
cd /home/zhangxiaohui/s3_stage3_v3_code
export MINIO_ALIAS=rp-monitor
export MINIO_BUCKET=rpki-probe-artifacts
export MINIO_PREFIX=rp-monitor/cd2
P9_PROBE_IDS=probe-cd bash scripts/runtime/run_runtime_retention_once.sh
```

CD2 three-probe checkpoint dry-run:

```bash
cd /home/zhangxiaohui/s3_stage3_v3_code
P9_PROBE_IDS=probe-cd,probe-sg,probe-k02 \
P9_CHECKPOINT=1 \
P9_UPLOAD_MINIO=0 \
bash scripts/runtime/run_runtime_retention_once.sh
```

## SGP2 Example

```bash
cd /home/zhangxiaohui/s3_stage3_v3_code
export MINIO_ALIAS=rp-monitor
export MINIO_BUCKET=rpki-probe-artifacts
export MINIO_PREFIX=rp-monitor/sgp2
P9_PROBE_IDS=probe-sg P9_P8_ROOT=data/probe/cross_probe_pipeline \
  bash scripts/runtime/run_runtime_retention_once.sh
```

## k02 Example

```bash
cd /home/zhangxiaohui/s3_stage3_v3_code
export MINIO_ALIAS=rp-monitor
export MINIO_BUCKET=rpki-probe-artifacts
export MINIO_PREFIX=rp-monitor/k02
P9_PROBE_IDS=probe-k02 bash scripts/runtime/run_runtime_retention_once.sh
```

## Validation

```bash
python -m py_compile \
  probe/build_p8_rollup.py \
  probe/manage_runtime_retention.py \
  probe/archive_snapshot_checkpoint.py

python probe/build_p8_rollup.py --help
python probe/manage_runtime_retention.py --help
python probe/archive_snapshot_checkpoint.py --help
bash -n scripts/runtime/run_runtime_retention_once.sh
bash scripts/runtime/run_runtime_retention_once.sh --help
```

Local dry-run without MinIO:

```bash
P9_UPLOAD_MINIO=0 bash scripts/runtime/run_runtime_retention_once.sh
latest_run="$(ls -dt data/probe/runtime_retention/p9_runtime_retention_* | head -1)"
cat "${latest_run}/retention/checks/P9_RUNTIME_RETENTION_ACCEPTANCE.txt"
python -m json.tool "${latest_run}/p8_rollup/p8_rollup_summary.json" >/dev/null
python -m json.tool "${latest_run}/retention/retention_report.json" >/dev/null
```
