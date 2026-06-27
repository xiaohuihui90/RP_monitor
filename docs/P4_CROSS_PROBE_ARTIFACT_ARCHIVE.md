# P4 Cross Probe Artifact Archive Manifest

P4 builds an offline archive manifest for cross-probe artifacts produced by P2
and optionally P3. It prepares the metadata needed by a future MinIO and database
archive path, but it does not upload objects and does not connect to a database.

P4 is intentionally separate from A-E, P1, P2, and P3. It should be run as an
explicit acceptance/archive preparation step.

## Inputs

Required P2 input:

```text
--p2-run-dir
```

The P2 run directory must contain:

- `cross_probe_summary.json`
- `cross_probe_events.jsonl`
- `candidate_events.jsonl`
- `checks/P2_CROSS_PROBE_DIFF_ACCEPTANCE.txt`

Optional P3 input:

```text
--p3-run-dir
```

The P3 run directory should contain:

- `summary.json`
- `persistent_events.jsonl`
- `semantic_divergences.jsonl`
- `transient_events.jsonl`
- `checks/P3_CROSS_WINDOW_PERSISTENCE_ACCEPTANCE.txt`

## Archived Artifacts

P4 uses an explicit artifact allowlist. It archives only the small P2/P3 outputs
listed above. It does not recursively archive the run directory and it does not
include any full `normalized_vrp.jsonl` or `latest_normalized_vrp.jsonl` files.

Each artifact entry includes:

- `artifact_type`
- `stage`
- `local_path`
- `relative_path`
- `exists`
- `size_bytes`
- `sha256`
- `suggested_minio_key`

## Metadata Extracted

From P2 `cross_probe_summary.json`, P4 extracts:

- `window_id`
- `window_quality`
- `probe_ids`
- `capture_time_by_probe`
- `capture_time_skew_sec`
- `event_count`
- `candidate_event_count`
- `missing_by_probe`

From P3 `summary.json`, P4 extracts:

- `accepted_window_count`
- `persistent_event_count`
- `semantic_divergence_count`
- `classification_distribution`
- `semantic_type_distribution`

## MinIO Key Rule

P4 only suggests keys. It does not connect to MinIO.

P2 artifacts:

```text
<minio_prefix>/cross_probe/window_id=<window_id>/p2/...
```

P3 artifacts:

```text
<minio_prefix>/cross_probe/window_id=<window_id>/p3/...
```

Example:

```text
rp-monitor/cross_probe/window_id=win_20260625T000000Z_1h/p2/cross_probe_summary.json
```

## Outputs

The output directory contains:

- `artifact_manifest.json`
- `db_rows_preview.json`
- `checks/P4_CROSS_PROBE_ARTIFACT_MANIFEST_ACCEPTANCE.txt`

`db_rows_preview.json` simulates rows for future tables:

- `cross_probe_windows`
- `cross_probe_persistence_runs`
- `cross_probe_artifacts`

## Acceptance Checks

The P4 acceptance file includes:

- `manifest_json_ok`
- `artifact_count_gt_zero`
- `all_artifacts_exist`
- `sha256_generated`
- `p2_summary_present`
- `p2_acceptance_present`
- `p3_summary_present` and `p3_acceptance_present` when `--p3-run-dir` is provided
- `no_normalized_vrp_in_manifest`

All checks must pass for `P4_CROSS_PROBE_ARTIFACT_MANIFEST=PASS`.

## Local Self Test

```bash
cd /path/to/RP_monitor

python -m py_compile probe/build_cross_probe_artifact_manifest.py
python probe/build_cross_probe_artifact_manifest.py --help

rm -rf /tmp/p4_cross_probe_manifest_self_test
python probe/build_cross_probe_artifact_manifest.py \
  --self-test \
  --out-dir /tmp/p4_cross_probe_manifest_self_test \
  --minio-bucket rpki-probe-artifacts \
  --minio-prefix rp-monitor

cat /tmp/p4_cross_probe_manifest_self_test/checks/P4_CROSS_PROBE_ARTIFACT_MANIFEST_ACCEPTANCE.txt
python -m json.tool /tmp/p4_cross_probe_manifest_self_test/artifact_manifest.json
python -m json.tool /tmp/p4_cross_probe_manifest_self_test/db_rows_preview.json
```

## CD2 Example

```bash
cd /path/to/RP_monitor

python probe/build_cross_probe_artifact_manifest.py \
  --p2-run-dir data/probe/p2_cross_probe/latest_window \
  --p3-run-dir data/probe/p3_cross_window/latest \
  --out-dir data/probe/p4_cross_probe_archive/$(date -u +%Y%m%dT%H%M%SZ) \
  --minio-bucket rpki-probe-artifacts \
  --minio-prefix rp-monitor
```

Inspect:

```bash
cat data/probe/p4_cross_probe_archive/*/checks/P4_CROSS_PROBE_ARTIFACT_MANIFEST_ACCEPTANCE.txt
```

P4 remains a manifest and metadata preview step. Use E5-style upload tooling or a
future cross-probe uploader to actually send objects to MinIO.
