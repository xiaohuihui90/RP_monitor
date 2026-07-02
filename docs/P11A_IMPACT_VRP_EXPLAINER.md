# P11-A Impact-Bearing Route-to-VRP Explainer

P11-A explains P10-A ROV transition events by reloading the window-bound VRP
snapshots archived for the same P8 window. It maps each impact-bearing BGP
route event back to candidate VRPs that can explain the observed state
difference across probes.

It does not claim root cause confirmation and does not assert real network
filtering or data-plane impact. All records keep:

```text
root_cause_confirmed=false
causal_claim_allowed=false
security_relevance=potential
```

## Inputs

Required:

```text
--p10a-run-dir PATH
--p8-input-vrp-manifest PATH
--out-dir PATH
```

Optional:

```text
--max-events N
--probe-ids probe-cd,probe-sg,probe-k02
```

P11-A reads:

```text
<p10a-run-dir>/validation_transition_events.jsonl
<p8-input-vrp-manifest>
```

The manifest must point at window-bound VRP files, usually:

```text
data/probe/p8_input_vrps/window_id=<window_id>/probe_id=<probe>/latest_normalized_vrp.jsonl.gz
```

P11-A intentionally does not read mutable current `latest_*` VRPs.

## ROV Recheck

For each P10-A transition event, P11-A recomputes RFC 6811 route origin
validation per probe:

```text
Valid    = at least one covering VRP with matching origin ASN
Invalid  = no matching VRP, but at least one covering VRP
NotFound = no covering VRP
```

It indexes VRPs by IP version and prefix length, then enumerates route
supernets. IPv4 and IPv6 are supported through Python `ipaddress`.

## Explainer Rules

For `Valid->NotFound`, the valid-side matching VRP is a candidate missing VRP.

For `NotFound->Valid`, the valid-side matching VRP is a candidate extra or newly
visible VRP.

For `Invalid->NotFound`, the invalid-side covering non-matching VRP is a
candidate missing covering VRP.

For `NotFound->Invalid`, the invalid-side covering non-matching VRP is a
candidate extra covering VRP.

For `Valid->Invalid` and `Invalid->Valid`, P11-A compares both matching VRPs and
covering non-matching VRPs.

VRP key:

```text
asn,prefix,max_length,tal
```

Mapping strength:

```text
strong = clear candidate VRP key explains the state difference
medium = covering VRP evidence exists but is not unique
weak   = only route-level event remains, no VRP candidate found
```

## Outputs

```text
impact_vrp_explanations.jsonl
impact_vrp_explanations.csv
route_level_vrp_summary.csv
top_candidate_vrps.csv
p11a_impact_vrp_explainer_summary.json
checks/P11A_IMPACT_VRP_EXPLAINER_ACCEPTANCE.txt
```

Important fields include:

```text
window_id
route_prefix
origin_asn
probe_a
probe_b
state_a
state_b
transition_type
explainer_type
candidate_vrp_probe
candidate_vrp_asn
candidate_vrp_prefix
candidate_vrp_max_length
candidate_vrp_tal
candidate_vrp_present_in_probes
candidate_vrp_missing_in_probes
covering_vrp_count_by_probe
matching_vrp_count_by_probe
recomputed_state_by_probe
mapping_strength
root_cause_confirmed
causal_claim_allowed
```

## Example

```bash
bash scripts/runtime/run_p11a_impact_vrp_explainer_once.sh \
  --p10a-run-dir data/probe/p10_rov_impact/win_20260701T070000Z_1h_routeviews2_20260701T060000Z_max500000 \
  --p8-input-vrp-manifest data/probe/p8_input_vrps/window_id=win_20260701T070000Z_1h/p8_input_vrp_manifest.json \
  --out-dir data/probe/p11a_impact_vrp_explainer/win_20260701T070000Z_1h_routeviews2_500k
```

Inspect:

```bash
cat data/probe/p11a_impact_vrp_explainer/win_20260701T070000Z_1h_routeviews2_500k/checks/P11A_IMPACT_VRP_EXPLAINER_ACCEPTANCE.txt
head -20 data/probe/p11a_impact_vrp_explainer/win_20260701T070000Z_1h_routeviews2_500k/top_candidate_vrps.csv
head -20 data/probe/p11a_impact_vrp_explainer/win_20260701T070000Z_1h_routeviews2_500k/route_level_vrp_summary.csv
```

Expected acceptance:

```text
P11A_IMPACT_VRP_EXPLAINER=PASS
transition_event_count > 0
explained_event_count > 0
strong_or_medium_mapping_count > 0
p8_input_vrp_manifest_loaded=true
all_probe_vrps_loaded=true
no_strong_root_cause_claim=true
```

## Validation

```bash
python -m py_compile probe/rov/*.py
bash -n scripts/runtime/run_p11a_impact_vrp_explainer_once.sh
bash scripts/runtime/run_p11a_impact_vrp_explainer_once.sh --help
```

Smoke with a small event cap:

```bash
bash scripts/runtime/run_p11a_impact_vrp_explainer_once.sh \
  --p10a-run-dir data/probe/p10_rov_impact/win_20260701T070000Z_1h_routeviews2_20260701T060000Z_max500000 \
  --p8-input-vrp-manifest data/probe/p8_input_vrps/window_id=win_20260701T070000Z_1h/p8_input_vrp_manifest.json \
  --out-dir data/probe/p11a_impact_vrp_explainer/p11a_smoke_win_20260701T070000Z_1h \
  --max-events 20
```

Do not commit `data/`, `logs/`, generated explainer outputs, paper tables, or
full VRP archives.
