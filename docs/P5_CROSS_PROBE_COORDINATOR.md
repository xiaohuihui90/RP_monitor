# P5 Cross Probe Coordinator

P5 runs one cross-probe observation from CD2. It gathers latest VRP snapshots
from multiple probe nodes, checks observation-window skew, and then invokes P2,
optionally P3 and P4.

P5 does not modify the A-E, P1, P2, or P3 scripts. It is a coordinator wrapper.
It does not hardcode private keys. Use `--ssh-command` when rsync needs a
specific SSH identity or option set.

## Workflow

One P5 run does this:

1. read local `probe-cd` latest snapshot from
   `data/probe/live_vrp_snapshots/probe-cd`;
2. optionally pull remote probe latest files with rsync;
3. check already-pushed remote snapshot directories such as
   `data/probe/remote_snapshots/probe-k02`;
4. load `latest_metadata.json` from each probe and compute capture-time skew;
5. if skew is acceptable, invoke P2 `diff_cross_probe_vrp_snapshots.py`;
6. if `--run-p3` is set, invoke P3 `analyze_cross_probe_persistence.py`;
7. if `--run-p4` is set, invoke P4 `build_cross_probe_artifact_manifest.py`;
8. write `run_summary.json` and
   `checks/P5_CROSS_PROBE_OBSERVATION_ACCEPTANCE.txt`.

P5 expects each probe directory to contain:

- `latest_metadata.json`
- `latest_normalized_vrp.jsonl`

## CD2 Example

```bash
cd /path/to/RP_monitor

python probe/run_cross_probe_observation_once.py \
  --probe-id-local probe-cd \
  --remote-probe probe-sg=zhangxiaohui@8.219.129.95:/home/zhangxiaohui/s3_stage3_v3_code/data/probe/live_vrp_snapshots/probe-sg \
  --remote-probe-local-dir probe-k02=data/probe/remote_snapshots/probe-k02 \
  --out-dir data/probe/p5_cross_probe_observations/$(date -u +%Y%m%dT%H%M%SZ) \
  --window-size-sec 3600 \
  --max-skew-sec 600 \
  --run-p3 \
  --run-p4 \
  --p3-min-consecutive 2 \
  --python-bin /home/zhangxiaohui/installers/ENTER/envs/s3-radar/bin/python \
  --ssh-command 'ssh -i ~/.ssh/id_ed25519 -o BatchMode=yes'
```

The SGP2 pull uses rsync and stores latest files under:

```text
data/probe/remote_snapshots/probe-sg/
```

The k02 input is not pulled by P5 in the command above; P5 only checks that k02
has already pushed files to:

```text
data/probe/remote_snapshots/probe-k02/
```

## Skew Behavior

By default, if:

```text
max(capture_time_utc) - min(capture_time_utc) > --max-skew-sec
```

P5 does not run P2 and writes a FAIL acceptance file with
`capture_time_by_probe` in `run_summary.json`.

For smoke testing only, you can allow a larger skew:

```bash
python probe/run_cross_probe_observation_once.py \
  ... \
  --max-skew-sec 600 \
  --allow-skew-up-to-sec 1800
```

When this is used and the skew is above the normal threshold but below the smoke
threshold, P5 runs P2 with the effective larger skew and sets:

```text
window_quality_warning=true
```

## Outputs

P5 writes:

- `run_summary.json`
- `checks/P5_CROSS_PROBE_OBSERVATION_ACCEPTANCE.txt`
- `p2_cross_probe/` when P2 runs
- `p3_persistence/` when `--run-p3` is set and P2 succeeds
- `p4_artifact_manifest/` when `--run-p4` is set and P2 succeeds

`run_summary.json` includes:

- remote pull status;
- snapshot paths;
- capture times by probe;
- validator health by probe;
- capture-time skew;
- command exit codes and stderr/stdout tails;
- P2/P3/P4 output paths and parsed summaries.

## Acceptance Checks

The acceptance file includes:

- `local_snapshot_exists`
- `remote_snapshot_exists`
- `metadata_json_ok`
- `all_validator_healthy`
- `capture_time_skew_within_threshold`
- `p2_exit_zero`
- `p2_window_quality_ok`
- `p2_acceptance_pass`
- `causal_claim_allowed_zero`
- `root_cause_confirmed_false`

All checks must pass for:

```text
P5_CROSS_PROBE_OBSERVATION=PASS
```

`all_validator_healthy` accepts exporter `validator_health` values `healthy` and
`degraded`, matching the exporter’s successful exit behavior.

## Self Test

P5 has a local synthetic self-test. It creates tiny local/remote latest snapshot
directories and runs P2, P3, and P4.

```bash
cd /path/to/RP_monitor

python -m py_compile probe/run_cross_probe_observation_once.py
python probe/run_cross_probe_observation_once.py --help

rm -rf /tmp/p5_cross_probe_observation_self_test
python probe/run_cross_probe_observation_once.py \
  --self-test \
  --out-dir /tmp/p5_cross_probe_observation_self_test \
  --python-bin "$(command -v python)"

cat /tmp/p5_cross_probe_observation_self_test/checks/P5_CROSS_PROBE_OBSERVATION_ACCEPTANCE.txt
python -m json.tool /tmp/p5_cross_probe_observation_self_test/run_summary.json
```

The self-test does not use rsync or SSH.

## Operational Notes

- Keep P5 out of the hourly E2 cron until cross-probe snapshot transfer is
  stable.
- Use `--ssh-command` for key selection; do not edit the script to add private
  key paths.
- If P5 fails before P2, inspect `snapshot_records`, `remote_pull_status`, and
  `capture_time_by_probe` in `run_summary.json`.
- If P2 runs but fails acceptance, inspect
  `p2_cross_probe/checks/P2_CROSS_PROBE_DIFF_ACCEPTANCE.txt`.
