# M24.5 Three-layer Continuous Monitoring Baseline Schema Catalog

Version: s3.m245.schema_catalog.v1

## 1. Window

Required fields:
- window_id
- window_start_utc
- window_end_utc
- window_size_sec

Default window size: 600 seconds.

Example:
{
  "window_id": "win_20260520T020000Z_10m",
  "window_start_utc": "2026-05-20T02:00:00Z",
  "window_end_utc": "2026-05-20T02:10:00Z",
  "window_size_sec": 600
}

## 2. Advertised View Record

Schema: s3.m245.advertised_view_record.v1

Required fields:
- schema
- window_id
- probe_id
- layer
- pp_id
- observed_at_utc
- notification_uri
- session_id
- serial
- notif_digest
- fetch_status
- failure_stage
- error_class
- latency_ms

## 3. Object View Light Record

Schema: s3.m245.object_view_light_record.v1

Required fields:
- schema
- window_id
- probe_id
- layer
- pp_id
- observed_at_utc
- object_set_root
- object_count
- manifest_count
- manifest_summary_root
- object_inventory_mode
- full_inventory_saved
- fetch_status
- failure_stage
- error_class
- latency_ms

## 4. Validation Output Light Record

Schema: s3.m245.validation_output_light_record.v1

Required fields:
- schema
- window_id
- probe_id
- layer
- observed_at_utc
- validator_name
- validator_version
- validator_refresh_interval_sec
- vrp_count
- vrp_root
- vrp_digest
- full_vrp_saved
- export_status
- failure_stage
- error_class
- latency_ms

## 5. Baseline Diff Record

Schema: s3.m245.baseline_diff_record.v1

Required fields:
- schema
- window_id
- diff_type
- layer
- pp_id
- probe_values
- affected_probes
- severity
- m25_trigger_required
- reason

## 6. M25 Trigger Candidate Record

Schema: s3.m245.m25_trigger_candidate_record.v1

Required fields:
- schema
- window_id
- trigger_id
- trigger_source
- trigger_layer
- trigger_event_type
- probe_scope
- priority
- requires_source_uri_expansion
- requires_m25_attribution
- requires_m26_interface
- input_window_summary

## 7. Run Manifest

Schema: s3.m245.run_manifest.v1

Required fields:
- schema
- run_id
- window_id
- created_at_utc
- role
- probe_id or collector_id
- artifacts
- checks
- summaries
