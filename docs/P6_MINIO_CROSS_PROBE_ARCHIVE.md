# P6 MinIO Cross Probe Archive

P6 consumes a P4 `artifact_manifest.json` and either builds a dry-run archive
plan or uploads verified cross-probe artifacts to MinIO with the `mc` CLI.

P6 does not use boto3. Dry-run mode does not require `mc`, MinIO credentials, or
network access.

## Inputs

```bash
python probe/archive_cross_probe_artifacts.py \
  --artifact-manifest data/probe/p4_cross_probe_archive/latest/artifact_manifest.json \
  --out-dir data/probe/p6_cross_probe_archive/latest \
  --mode dry-run
```

Required:

- `--artifact-manifest`: P4 `artifact_manifest.json`
- `--out-dir`

Optional:

- `--mode dry-run|upload`, default `dry-run`
- `--minio-endpoint`
- `--minio-bucket`
- `--access-key-env`, default `MINIO_ACCESS_KEY`
- `--secret-key-env`, default `MINIO_SECRET_KEY`
- `--compress-jsonl`
- `--compression-format gz`

## Dry Run

Dry-run mode:

- loads the P4 manifest;
- verifies each artifact `local_path`, `size_bytes`, and `sha256`;
- plans object keys from each artifact's `suggested_minio_key`;
- writes report and acceptance files;
- does not call `mc`;
- does not connect to MinIO.

Outputs:

- `archive_plan.json`
- `archive_report.json`
- `checks/P6_MINIO_ARCHIVE_ACCEPTANCE.txt`

## Upload Mode

Upload mode requires the MinIO `mc` CLI in `PATH`. If `mc` is missing, P6 writes a
clear failure into `archive_report.json` and the acceptance check fails.

P6 uses:

```bash
mc alias set rp-monitor-p6 <endpoint> <access_key> <secret_key>
mc cp <local_file> rp-monitor-p6/<bucket>/<object_key>
mc stat --json rp-monitor-p6/<bucket>/<object_key>
```

Credentials are read from environment variables:

```bash
export MINIO_ACCESS_KEY=...
export MINIO_SECRET_KEY=...
```

Then run:

```bash
python probe/archive_cross_probe_artifacts.py \
  --artifact-manifest data/probe/p4_cross_probe_archive/latest/artifact_manifest.json \
  --out-dir data/probe/p6_cross_probe_archive/latest \
  --mode upload \
  --minio-endpoint http://127.0.0.1:9000 \
  --minio-bucket rpki-probe-artifacts
```

After upload, P6 records the object key and, when `mc stat --json` succeeds,
captures size, etag, and metadata from the stat output.

## Compression

`--compress-jsonl` stores `.jsonl` artifacts as `.jsonl.gz` objects. The original
artifact file is never modified. In upload mode, compressed staging files are
written under:

```text
<out-dir>/staging/
```

Dry-run mode only records the compression plan and does not materialize
compressed files.

## Normalized VRP Guard

P6 does not upload full `normalized_vrp.jsonl` or `latest_normalized_vrp.jsonl`
artifacts by default when their `artifact_type` is `normalized_vrp` or otherwise
contains `normalized_vrp`.

P4 normally excludes these large files already. P6 keeps the guard as a second
line of defense. If a manifest explicitly contains a path with
`normalized_vrp.jsonl` but uses a non-normalized artifact type, P6 treats it as an
explicit manifest decision.

## Acceptance

`checks/P6_MINIO_ARCHIVE_ACCEPTANCE.txt` includes:

- `artifact_count_gt_zero`
- `all_artifacts_verified`
- `no_normalized_vrp_by_default`
- `upload_failed_count_zero`
- `archive_report_json_ok`

All checks must pass for:

```text
P6_MINIO_ARCHIVE=PASS
```

## Local Dry Run Acceptance

```bash
cd /path/to/RP_monitor

python -m py_compile probe/archive_cross_probe_artifacts.py
python probe/archive_cross_probe_artifacts.py --help

python probe/archive_cross_probe_artifacts.py \
  --artifact-manifest /path/to/p4/artifact_manifest.json \
  --out-dir /tmp/p6_cross_probe_archive_dry_run \
  --mode dry-run \
  --compress-jsonl \
  --compression-format gz

python -m json.tool /tmp/p6_cross_probe_archive_dry_run/archive_plan.json
python -m json.tool /tmp/p6_cross_probe_archive_dry_run/archive_report.json
cat /tmp/p6_cross_probe_archive_dry_run/checks/P6_MINIO_ARCHIVE_ACCEPTANCE.txt
```

## CD2 Dry Run Example

```bash
cd /path/to/RP_monitor

latest_p4="$(ls -td data/probe/p4_cross_probe_archive/* | head -n 1)"

python probe/archive_cross_probe_artifacts.py \
  --artifact-manifest "$latest_p4/artifact_manifest.json" \
  --out-dir "data/probe/p6_cross_probe_archive/$(date -u +%Y%m%dT%H%M%SZ)" \
  --mode dry-run \
  --compress-jsonl \
  --compression-format gz
```

P6 is safe to run repeatedly in dry-run mode. Upload mode should be enabled only
after P4 manifests and MinIO credentials are confirmed.
