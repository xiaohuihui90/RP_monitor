# P7 MinIO Archive Verify And Restore Smoke Test

P7 verifies cross-probe artifacts after P6 upload. It reads a P6
`archive_report.json`, loads the sibling `archive_plan.json`, and uses the MinIO
`mc` CLI to check uploaded objects.

P7 does not use boto3 and does not change A-E or P1-P6 behavior.

## Inputs

```bash
python probe/verify_minio_cross_probe_archive.py \
  --archive-report data/probe/p6_cross_probe_archive/latest/archive_report.json \
  --out-dir data/probe/p7_cross_probe_verify/latest
```

Required:

- `--archive-report`: P6 `archive_report.json`
- `--out-dir`

Optional:

- `--archive-plan`: override plan path. By default P7 reads
  `archive_plan.json` next to `archive_report.json`.
- `--mc-bin`: MinIO `mc` command or path. Default is `mc`.
- `--sample-download N`: download N uploaded objects to
  `out-dir/restore_sample/` and verify SHA-256.
- `--include-normalized-vrp-samples`: allow normalized VRP objects in the
  restore sample. Default is false.

## What P7 Verifies

For every artifact whose P6 plan says:

```text
upload_status=uploaded
```

P7 runs:

```bash
mc stat --json <mc_target>
```

It records:

- object key / target;
- stat size;
- etag, when present;
- metadata, when present;
- stat errors.

P7 checks object size against the per-object archive size in P6
`archive_plan.json`. If the object was uploaded compressed, P6 records the
compressed archive size and SHA-256, and P7 uses those archive values.

## Restore Smoke Test

With `--sample-download N`, P7 downloads up to N uploaded objects:

```bash
mc cp <mc_target> <out-dir>/restore_sample/<sample_file>
```

It then recalculates SHA-256 and compares it to the archive SHA-256 recorded by
P6. If no archive SHA-256 is present, it falls back to the source SHA-256.

By default, P7 does not sample-download `normalized_vrp.jsonl` or
`latest_normalized_vrp.jsonl` objects. P4/P6 normally exclude these large files
already, and this default keeps restore smoke tests lightweight.

## Outputs

P7 writes:

- `verify_report.json`
- `restored_samples.jsonl`
- `checks/P7_MINIO_ARCHIVE_VERIFY_ACCEPTANCE.txt`

The report keeps the semantic boundary:

- `causal_claim_allowed=false`
- `root_cause_confirmed=false`

P7 verifies archive integrity only; it does not claim root cause.

## Acceptance

The acceptance file includes:

- `archive_report_json_ok`
- `uploaded_object_count_gt_zero`
- `stat_failed_count_zero`
- `size_mismatch_count_zero`
- `sample_sha256_mismatch_count_zero`

Additional compatibility checks are also written:

- `archive_plan_json_ok`
- `causal_claim_allowed_false`
- `root_cause_confirmed_false`

All checks must pass for:

```text
P7_MINIO_ARCHIVE_VERIFY=PASS
```

If the input was a P6 dry-run report, no objects were uploaded, so P7 will fail
with `uploaded_object_count_gt_zero=false`. That is expected.

## Local Checks

```bash
cd /path/to/RP_monitor

python -m py_compile probe/verify_minio_cross_probe_archive.py
python probe/verify_minio_cross_probe_archive.py --help
```

## Verify Uploaded Archive

After a successful P6 upload:

```bash
python probe/verify_minio_cross_probe_archive.py \
  --archive-report data/probe/p6_cross_probe_archive/latest/archive_report.json \
  --out-dir data/probe/p7_cross_probe_verify/$(date -u +%Y%m%dT%H%M%SZ) \
  --mc-bin mc \
  --sample-download 3
```

Inspect:

```bash
python -m json.tool data/probe/p7_cross_probe_verify/*/verify_report.json
cat data/probe/p7_cross_probe_verify/*/checks/P7_MINIO_ARCHIVE_VERIFY_ACCEPTANCE.txt
head -n 5 data/probe/p7_cross_probe_verify/*/restored_samples.jsonl
```

## CD2 Notes

- Ensure the same `mc` alias used by P6 remains configured. P6 currently records
  object targets like `rp-monitor-p6/<bucket>/<key>` in `archive_plan.json`.
- If `mc` is missing, install/configure it before running P7 upload verification.
- P7 does not read MinIO secrets directly; it relies on the existing `mc`
  configuration and the object targets stored by P6.
