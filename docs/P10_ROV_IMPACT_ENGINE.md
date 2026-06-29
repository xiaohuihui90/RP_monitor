# P10 ROV Impact Engine

P10 maps cross-probe VRP view differences to Route Origin Validation state
differences over a common BGP route table.

The engine answers a deliberately narrow question:

```text
Given the same BGP prefix-origin route table, do different probe VRP views
produce different RFC 6811 ROV states?
```

It does not prove real traffic loss, real route filtering, or that an operator
uses reject-invalid policy.

## Inputs

First-stage mode is `rib_snapshot`.

```bash
bash scripts/runtime/run_p10_rov_impact_once.sh \
  --mode rib_snapshot \
  --routes data/bgp/latest_prefix_origin.csv \
  --vrp probe-cd=data/probe/live_vrp_snapshots/probe-cd/latest_normalized_vrp.jsonl \
  --metadata probe-cd=data/probe/live_vrp_snapshots/probe-cd/latest_metadata.json \
  --vrp probe-sg=data/probe/remote_snapshots/probe-sg/latest_normalized_vrp.jsonl \
  --metadata probe-sg=data/probe/remote_snapshots/probe-sg/latest_metadata.json \
  --vrp probe-k02=data/probe/remote_snapshots/probe-k02/latest_normalized_vrp.jsonl \
  --metadata probe-k02=data/probe/remote_snapshots/probe-k02/latest_metadata.json \
  --p8-run-dir data/probe/cross_probe_pipeline/<latest_p8_run> \
  --out-dir data/probe/p10_rov_impact/<run_id>
```

Routes may be CSV or JSONL. Required route fields:

- `prefix`
- `origin_asn`

Optional route fields:

- `collector`
- `observed_time_utc`
- `peer_asn`
- `source_type`

## RFC 6811 Semantics

For a BGP route `r=(prefix P, origin AS O)` and a VRP
`v=(prefix V, maxLength M, ASN A)`:

- `covered`: `V` covers `P` and `prefix_len(P) <= M`
- `matched`: `covered` and `O == A`
- if any `matched` VRP exists, the route is `Valid`
- else if any `covered` VRP exists, the route is `Invalid`
- otherwise the route is `NotFound`

The implementation supports IPv4 and IPv6 using Python `ipaddress`.

VRPs are indexed as:

```text
IP version -> prefix length -> network -> list[vrp]
```

Route lookup enumerates route supernets instead of scanning the full VRP table.

## Time Alignment

P10 aligns:

- route table time, from `--route-time-utc` or route `observed_time_utc`;
- VRP capture times, from each probe `latest_metadata.json`;
- optional P8 window metadata from `--p8-run-dir`.

If no route time is available, P10 uses the VRP window center as an inferred
route time. For stricter experiments, pass `--route-time-utc`.

Default route-time skew limit:

```text
--max-route-time-skew-sec 7200
```

Default VRP capture skew limit:

```text
--max-vrp-skew-sec 600
```

## Quality Gates

Normal impact analysis is executed only when all gates pass:

1. all metadata files exist;
2. all metadata JSON files parse;
3. every `validator_health` is exactly `healthy`;
4. capture time skew is within `--max-vrp-skew-sec`;
5. all probes have complete TAL coverage;
6. `min(vrp_count) / median(vrp_count) >= --min-vrp-count-ratio`;
7. route time is close enough to the VRP window center.

Default required TALs:

```text
apnic,arin,ripe,lacnic,afrinic
```

Partial TAL view is explicitly detected. For example, a probe with only APNIC
and LACNIC VRPs and missing ARIN/RIPE/AFRINIC is excluded from normal impact
statistics and recorded in `abnormal_window_report.json`.

If any quality gate fails, P10 writes:

```text
P10_ROV_IMPACT=PASS_WITH_EXCLUSIONS
```

and does not run normal control-plane impact analysis.

## Modes

### rib_snapshot

`rib_snapshot` validates a static BGP prefix-origin route table against each
probe's VRP view.

This mode is implemented in the first version.

### update_replay

`update_replay` is the future mode for time-window route table reconstruction:

```bash
python -m probe.rov.analyze_rov_impact \
  --mode update_replay \
  --rib PATH \
  --updates-dir PATH \
  --collector route-views.sg \
  --window-start-utc 2026-06-29T00:00:00Z \
  --window-end-utc 2026-06-29T01:00:00Z \
  --out-dir data/probe/p10_rov_impact/update_replay_schema
```

The current version writes a stable skipped schema and documents the future
route-table output contract. It does not replay UPDATEs yet.

## Outputs

`route_state_by_probe.jsonl`

One row per route with per-probe states and compact covering VRP evidence.

`validation_transition_events.jsonl`

Only routes whose ROV state differs across probes. Each event is
`security_relevance=potential`.

`transition_matrix.csv`

Counts by probe pair and state transition.

`affected_prefix_summary.csv`

Counts and probe-pair summaries per affected prefix-origin.

`affected_origin_as_summary.csv`

Affected prefix counts per origin AS.

`tal_impact_summary.csv`

TAL-level summaries when TAL can be inferred from covering VRPs.

`abnormal_window_report.json`

Always written. Contains quality-gate evidence and exclusion reasons.

`checks/P10_ROV_IMPACT_ACCEPTANCE.txt`

Machine-readable acceptance file.

## Transition Classes

```text
Valid->NotFound    ROV_DOWNGRADE_CANDIDATE
Valid->Invalid     FALSE_REJECT_RISK
Invalid->Valid     STALE_OR_OVERPERMISSIVE_VALID_CANDIDATE
NotFound->Invalid  NEW_REJECT_RISK
Invalid->NotFound  REJECT_TO_UNKNOWN_CHANGE
NotFound->Valid    NEW_AUTHORIZATION_VISIBLE
```

Same-state probe pairs are not emitted as transition events.

## Interpretation

P10 supports this evidence chain:

```text
VRP diff -> ROV-state diff -> potentially policy-relevant control-plane impact
```

It does not claim:

- real route rejection happened;
- real traffic was affected;
- a particular network deployed reject-invalid;
- a root cause is confirmed.

Those claims require future evidence from ROV deployment, route propagation,
policy, or data-plane measurements.

## Validation

```bash
python -m py_compile \
  probe/rov/__init__.py \
  probe/rov/rov_validate.py \
  probe/rov/load_vrps.py \
  probe/rov/load_bgp_routes.py \
  probe/rov/build_bgp_route_table.py \
  probe/rov/compute_rov_state_by_probe.py \
  probe/rov/analyze_rov_impact.py

python -m probe.rov.analyze_rov_impact --help
bash -n scripts/runtime/run_p10_rov_impact_once.sh
bash scripts/runtime/run_p10_rov_impact_once.sh --help
```

Quality-gate test expectation:

- a partial TAL probe should produce `P10_ROV_IMPACT=PASS_WITH_EXCLUSIONS`;
- `normal_impact_analysis_executed=false`;
- `abnormal_window_report.json` should include `PARTIAL_TAL_VIEW`.
