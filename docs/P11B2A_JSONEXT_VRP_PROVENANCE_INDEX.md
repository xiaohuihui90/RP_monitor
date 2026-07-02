# P11-B2A Routinator JSONEXT VRP Provenance Index

P11-B2A builds the first object-provenance index that P11-B can consume
directly:

```text
candidate_vrp_key -> roa_uri / source_uri / TAL / validity / chainValidity / stale
```

The source is Routinator `vrps --format jsonext`. JSONEXT records expose
`roas[*].source[*]`, including:

```text
source.type
source.tal
source.uri
source.validity
source.chainValidity
source.stale
```

P11-B2A does not parse ROA or manifest objects. Manifest URI, manifest number,
and object hashes are intentionally left blank unless a later P11-B2B object
layer fills them.

No output claims root cause confirmation:

```text
root_cause_confirmed=false
causal_claim_allowed=false
```

## Inputs

Required:

```text
--p11a-run-dir PATH
--p8-input-vrp-manifest PATH
--out-dir PATH
```

Optional:

```text
--routinator-bin PATH
--jsonext-file PATH
--probe-id PROBE
--max-candidates N
--use-window-bound-jsonext-if-available true|false
```

P11-B2A reads P11-A candidates from:

```text
<p11a-run-dir>/top_candidate_vrps.csv
<p11a-run-dir>/impact_vrp_explanations.jsonl
```

Candidate key format:

```text
asn_without_AS,prefix,maxLength,tal
```

Example:

```text
13335,1.1.1.0/24,24,apnic
```

## JSONEXT Source Selection

P11-B2A first uses `--jsonext-file` if provided.

If no explicit file is provided and
`--use-window-bound-jsonext-if-available true`, it searches near the
window-bound P8 input manifest and P8 run directory for:

```text
latest_vrps_jsonext.json
jsonext_vrps.json
routinator_jsonext.json
vrps.jsonext.raw.json
probe_id=<probe>/latest_vrps_jsonext.json
```

`.gz` variants are supported.

If no window-bound JSONEXT is available, P11-B2A attempts a current capture:

```bash
routinator vrps --format jsonext --output <out-dir>/current_routinator_jsonext.json
```

If that command is unavailable or fails, outputs are still written with
unresolved candidates.

Important semantic boundary:

```text
provenance_time_mode=window_bound
```

means the JSONEXT file was found in the P8/window-bound area or explicitly
provided from that area.

```text
provenance_time_mode=current_not_window_bound
```

means P11-B2A captured current Routinator JSONEXT. This is useful for debugging
and mapping coverage, but it is not historical same-window evidence.

## Outputs

```text
vrp_object_mapping_index.jsonl
vrp_object_mapping_index.csv
matched_candidate_vrps.csv
unresolved_candidate_vrps.csv
jsonext_parse_summary.json
checks/P11B2A_JSONEXT_PROVENANCE_INDEX_ACCEPTANCE.txt
```

`vrp_object_mapping_index.jsonl` is directly usable by P11-B:

```bash
bash scripts/runtime/run_p11b_vrp_object_mapper_once.sh \
  --p11a-run-dir data/probe/p11a_impact_vrp_explainer/<P11A_RUN> \
  --p8-input-vrp-manifest data/probe/p8_input_vrps/window_id=<WINDOW_ID>/p8_input_vrp_manifest.json \
  --mapping-index data/probe/p11b2a_jsonext_provenance/<RUN_ID>/vrp_object_mapping_index.jsonl \
  --out-dir data/probe/p11b_vrp_object_mapping/<P11B_RUN>
```

Index fields include:

```text
candidate_vrp_key
asn
prefix
max_length
tal
roa_uri
source_uri
roa_hash
manifest_uri
manifest_hash
manifest_number
manifest_this_update
manifest_next_update
publication_point
ca_repository_uri
rrdp_uri
rsync_uri
validity_not_before
validity_not_after
chain_validity_not_before
chain_validity_not_after
stale
mapping_strength
mapping_reason
mapping_source_file
provenance_source=jsonext
provenance_time_mode=window_bound|current_not_window_bound
root_cause_confirmed=false
causal_claim_allowed=false
```

Mapping strength:

```text
medium = JSONEXT ROA source URI exists
weak   = JSONEXT TAL-only source evidence exists
none   = candidate VRP was not found in JSONEXT
```

## Acceptance

`PASS`:

```text
candidate_vrp_count > 0
jsonext_loaded_or_generated=true
index_written=true
mapped_candidate_vrp_count > 0
no_strong_root_cause_claim=true
```

`PASS_WITH_EXCLUSIONS`:

```text
candidate_vrp_count > 0
jsonext_loaded_or_generated=false or mapped_candidate_vrp_count=0
unresolved_candidate_vrp_count > 0
outputs_written=true
no_strong_root_cause_claim=true
```

`FAIL` only means P11-A cannot be read, no candidate VRPs were found, or outputs
could not be written.

## Example

With explicit window-bound JSONEXT:

```bash
bash scripts/runtime/run_p11b2a_jsonext_provenance_index_once.sh \
  --p11a-run-dir data/probe/p11a_impact_vrp_explainer/p11a_win_20260701T070000Z_1h_500k_20260702T020930Z \
  --p8-input-vrp-manifest data/probe/p8_input_vrps/window_id=win_20260701T070000Z_1h/p8_input_vrp_manifest.json \
  --jsonext-file data/probe/p8_input_vrps/window_id=win_20260701T070000Z_1h/latest_vrps_jsonext.json \
  --out-dir data/probe/p11b2a_jsonext_provenance/p11b2a_win_20260701T070000Z_1h_500k
```

Allow fallback to current Routinator JSONEXT:

```bash
bash scripts/runtime/run_p11b2a_jsonext_provenance_index_once.sh \
  --p11a-run-dir data/probe/p11a_impact_vrp_explainer/p11a_win_20260701T070000Z_1h_500k_20260702T020930Z \
  --p8-input-vrp-manifest data/probe/p8_input_vrps/window_id=win_20260701T070000Z_1h/p8_input_vrp_manifest.json \
  --routinator-bin "$HOME/.cargo/bin/routinator" \
  --out-dir data/probe/p11b2a_jsonext_provenance/p11b2a_current_jsonext_smoke
```

Inspect:

```bash
cat data/probe/p11b2a_jsonext_provenance/<RUN_ID>/checks/P11B2A_JSONEXT_PROVENANCE_INDEX_ACCEPTANCE.txt
head -20 data/probe/p11b2a_jsonext_provenance/<RUN_ID>/matched_candidate_vrps.csv
head -20 data/probe/p11b2a_jsonext_provenance/<RUN_ID>/unresolved_candidate_vrps.csv
```

## Validation

```bash
python -m py_compile probe/rov/*.py
bash -n scripts/runtime/run_p11b2a_jsonext_provenance_index_once.sh
python -m probe.rov.build_jsonext_vrp_provenance_index --help
```

Do not commit generated `data/`, `logs/`, `paper_tables`, or check outputs.
