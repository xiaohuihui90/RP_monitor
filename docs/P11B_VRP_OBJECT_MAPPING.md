# P11-B Candidate VRP Object Mapping

P11-B consumes P11-A candidate VRP explanations and maps candidate VRP keys to
object-level evidence context when an index is available:

- ROA URI and hash
- manifest URI, hash, manifest number, thisUpdate, nextUpdate
- publication point
- CA repository URI
- TAL

It does not parse RPKI objects from scratch. It reuses existing mapping and
evidence artifacts where present, including M19/M22/M23/SEC27-style JSONL/CSV
indexes. If no mapping index exists, P11-B still writes candidate VRP-level
records and returns `PASS_WITH_EXCLUSIONS`.

P11-B never sets:

```text
root_cause_confirmed=true
causal_claim_allowed=true
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
--mapping-index PATH
--object-evidence-root PATH
--max-candidates N
```

P11-B reads:

```text
<p11a-run-dir>/impact_vrp_explanations.jsonl
<p11a-run-dir>/top_candidate_vrps.csv
<p8-input-vrp-manifest>
```

The manifest is provenance only for this stage. P11-B does not read mutable
current `latest_*` VRPs.

## Mapping Indexes

`--mapping-index` may point to one JSONL/CSV/JSON file or a directory. If it is
a directory, P11-B scans JSONL/CSV/JSON files below it.

`--object-evidence-root` is an additional directory scan root.

If neither option is given, P11-B checks common SEC27 evidence paths:

```text
data/p3_analysis/sec27/b4c_candidate_evidence_table/candidate_evidence_table.jsonl
data/p3_analysis/sec27/b5_paper_stats/object_or_manifest_supported_subset.jsonl
data/p3_analysis/sec27/b6_final_paper_tables/selected_persistent_cases.jsonl
data/p3_analysis/sec27/l2b_effective_input_r2/l2b_candidate_effective_input.jsonl
```

The loader is field-compatible rather than schema-specific. It tries keys such
as:

```text
candidate_vrp_key
vrp_key
derived_tuple_key
diff_vrp_key
tal/asn/prefix/max_length
```

Object fields are inferred from common names:

```text
roa_uri, object_uri, file_uri, source_uri
roa_hash, object_hash, manifest_file_hash
manifest_uri, matched_manifest_uri
publication_point, publication_point_dir, pp_uri, repo_base
ca_repository_uri, ca_repo_uri
```

## Outputs

```text
candidate_vrp_object_mapping.jsonl
candidate_vrp_object_mapping.csv
top_pp_by_candidate_vrp.csv
top_ca_by_candidate_vrp.csv
top_tal_by_candidate_vrp.csv
unresolved_candidate_vrps.csv
p11b_vrp_object_mapping_summary.json
checks/P11B_VRP_OBJECT_MAPPING_ACCEPTANCE.txt
```

Core output fields:

```text
window_id
route_prefix
origin_asn
candidate_vrp_key
candidate_vrp_asn
candidate_vrp_prefix
candidate_vrp_max_length
candidate_vrp_tal
candidate_vrp_present_in_probes
candidate_vrp_missing_in_probes
roa_uri
roa_hash
manifest_uri
manifest_hash
manifest_number
manifest_this_update
manifest_next_update
publication_point
ca_repository_uri
tal
object_mapping_strength
object_mapping_reason
root_cause_confirmed=false
causal_claim_allowed=false
```

Mapping strength:

```text
strong = object hash or ROA/manifest hash-chain evidence is present
medium = ROA/manifest/publication-point context is present
weak   = no object mapping, or only route/VRP-level context remains
```

## Acceptance

`PASS`:

```text
p11a_loaded=true
candidate_vrp_count > 0
output_files_written=true
no_strong_root_cause_claim=true
```

`PASS_WITH_EXCLUSIONS`:

```text
candidate_vrp_count > 0
no mapping index exists
unresolved_candidate_vrp_count > 0
outputs are still written with object_mapping_reason=NO_MAPPING_INDEX
```

`FAIL` only means P11-A input could not be read, no candidate VRPs were found,
or output files could not be written.

## Example

```bash
bash scripts/runtime/run_p11b_vrp_object_mapper_once.sh \
  --p11a-run-dir data/probe/p11a_impact_vrp_explainer/p11a_win_20260701T070000Z_1h_500k_20260702T020930Z \
  --p8-input-vrp-manifest data/probe/p8_input_vrps/window_id=win_20260701T070000Z_1h/p8_input_vrp_manifest.json \
  --mapping-index data/p3_analysis/sec27/b4c_candidate_evidence_table/candidate_evidence_table.jsonl \
  --out-dir data/probe/p11b_vrp_object_mapping/p11b_win_20260701T070000Z_1h_500k
```

Fallback without an index:

```bash
bash scripts/runtime/run_p11b_vrp_object_mapper_once.sh \
  --p11a-run-dir data/probe/p11a_impact_vrp_explainer/p11a_win_20260701T070000Z_1h_500k_20260702T020930Z \
  --p8-input-vrp-manifest data/probe/p8_input_vrps/window_id=win_20260701T070000Z_1h/p8_input_vrp_manifest.json \
  --out-dir data/probe/p11b_vrp_object_mapping/p11b_no_index_smoke
```

Inspect:

```bash
cat data/probe/p11b_vrp_object_mapping/p11b_win_20260701T070000Z_1h_500k/checks/P11B_VRP_OBJECT_MAPPING_ACCEPTANCE.txt
head -20 data/probe/p11b_vrp_object_mapping/p11b_win_20260701T070000Z_1h_500k/candidate_vrp_object_mapping.csv
head -20 data/probe/p11b_vrp_object_mapping/p11b_win_20260701T070000Z_1h_500k/unresolved_candidate_vrps.csv
```

## Validation

```bash
python -m py_compile probe/rov/*.py
bash -n scripts/runtime/run_p11b_vrp_object_mapper_once.sh
python -m probe.rov.map_candidate_vrps_to_objects --help
```

Do not commit generated `data/`, `logs/`, paper tables, or full VRP archives.
