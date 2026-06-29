# P10-B1 BGP Route Table Builder

P10-B1 converts a local RouteViews or RIPE RIS MRT RIB into the `routes.jsonl`
format accepted by the P10 ROV Impact Engine.

It answers a narrow plumbing question:

```text
Can this local RIB snapshot be converted into prefix-origin routes that P10-A
can validate against the three probe VRP views?
```

It does not download new RIBs, replay UPDATEs, or claim time-aligned
control-plane impact by itself.

## Relationship To P10-A

P10-A (`probe.rov.analyze_rov_impact`) consumes route tables in CSV or JSONL.
P10-B1 builds that route table from a local MRT RIB using `bgpdump -m`.

The output can be passed directly to P10-A:

```bash
bash scripts/runtime/run_p10_rov_impact_once.sh \
  --mode rib_snapshot \
  --routes data/bgp/p10_route_tables/routeviews2_20260101T000000Z/routes.jsonl \
  --vrp probe-cd=data/probe/live_vrp_snapshots/probe-cd/latest_normalized_vrp.jsonl \
  --metadata probe-cd=data/probe/live_vrp_snapshots/probe-cd/latest_metadata.json \
  --vrp probe-sg=data/probe/remote_snapshots/probe-sg/latest_normalized_vrp.jsonl \
  --metadata probe-sg=data/probe/remote_snapshots/probe-sg/latest_metadata.json \
  --vrp probe-k02=data/probe/remote_snapshots/probe-k02/latest_normalized_vrp.jsonl \
  --metadata probe-k02=data/probe/remote_snapshots/probe-k02/latest_metadata.json \
  --p8-run-dir data/probe/cross_probe_pipeline/<P8_PASS_RUN> \
  --out-dir data/probe/p10_rov_impact/<run_id>
```

If the RIB time is far from the P8 window, P10-A should report
`PASS_WITH_EXCLUSIONS` or `SKIPPED`. That is expected and protects the analysis
from stale control-plane inputs.

## Why Only rib_snapshot

This stage intentionally implements only local RIB snapshot conversion. Full
UPDATE replay needs a separate time-window route reconstruction design:

- initial RIB state;
- UPDATE add/withdraw replay;
- collector and peer-specific route selection semantics;
- stable window route-table schema.

P10-B1 keeps the current milestone small: one local RIB in, one P10-ready route
JSONL out.

## Inputs

```bash
bash scripts/runtime/run_p10_build_route_table_once.sh \
  --rib data/bgp/routeviews/ribs/rib.20260101.0000.bz2 \
  --collector routeviews2 \
  --rib-time-utc 2026-01-01T00:00:00Z \
  --out-dir data/bgp/p10_route_tables/routeviews2_20260101T000000Z \
  --max-routes 100000
```

Main options:

- `--rib PATH`: local MRT RIB. `.bz2` is supported when `bgpdump` supports it.
- `--collector COLLECTOR_ID`: for example `routeviews2` or `rrc00`.
- `--rib-time-utc YYYY-MM-DDTHH:MM:SSZ`: RIB timestamp stored on each route.
- `--out-dir PATH`: output directory.
- `--bgpdump-bin PATH`: defaults to `bgpdump`; no path is hardcoded.
- `--max-routes N`: stop after N unique routes for smoke runs.
- `--include-ipv6` / `--no-include-ipv6`: IPv6 is included by default.
- `--as-set-policy skip|mark_uncertain`: default `skip`.
- `--dedupe-key prefix_origin_collector|prefix_origin|none`: default
  `prefix_origin_collector`.

## AS_PATH Handling

Origin AS is the last ordinary ASN in `AS_PATH`. Tokens such as `123` and
`AS123` are accepted.

Default behavior:

- AS_SET segments like `{1,2}` are skipped and counted in
  `skipped_as_set_count`.
- confederation segments like `(65000 65001)` are skipped and counted in
  `skipped_confed_count`.
- malformed prefixes or missing origin AS values increment `parse_error_count`
  without crashing the run.

With `--as-set-policy mark_uncertain`, routes containing AS_SET or confed
syntax are retained when an ordinary origin ASN can still be extracted. Those
rows have `as_path_uncertain=true`.

## Output Schema

`routes.jsonl` contains one JSON object per route:

```json
{
  "schema": "s3.probe.rov.bgp_route.v1",
  "prefix": "1.1.1.0/24",
  "origin_asn": 13335,
  "collector": "routeviews2",
  "observed_time_utc": "2026-01-01T00:00:00Z",
  "peer_asn": 6447,
  "peer_ip": "198.32.160.1",
  "source_type": "rib_snapshot",
  "rib_path": "data/bgp/routeviews/ribs/rib.20260101.0000.bz2",
  "rib_time_utc": "2026-01-01T00:00:00Z",
  "as_path": "6447 13335",
  "as_path_uncertain": false,
  "route_key": "routeviews2|1.1.1.0/24|13335"
}
```

`route_build_summary.json` contains:

- RIB path and SHA-256;
- collector and RIB time;
- raw and unique route counts;
- IPv4/IPv6 counts;
- skipped AS_SET/confed counts;
- parse error count;
- bgpdump availability and exit code;
- output file paths.

`checks/P10_BGP_ROUTE_TABLE_ACCEPTANCE.txt` records the run status and machine
checks.

## Local Smoke With Existing RIB

The repository currently has an old RouteViews RIB:

```text
data/bgp/routeviews/ribs/rib.20260101.0000.bz2
```

Use it only to test the converter:

```bash
python -m py_compile probe/rov/*.py

bash -n scripts/runtime/run_p10_build_route_table_once.sh
bash -n scripts/runtime/run_p10_rov_impact_once.sh

bash scripts/runtime/run_p10_build_route_table_once.sh \
  --rib data/bgp/routeviews/ribs/rib.20260101.0000.bz2 \
  --collector routeviews2 \
  --rib-time-utc 2026-01-01T00:00:00Z \
  --out-dir data/bgp/p10_route_tables/routeviews2_20260101T000000Z \
  --max-routes 100000

cat data/bgp/p10_route_tables/routeviews2_20260101T000000Z/checks/P10_BGP_ROUTE_TABLE_ACCEPTANCE.txt
head -n 3 data/bgp/p10_route_tables/routeviews2_20260101T000000Z/routes.jsonl
```

Then run P10-A against the generated route table:

```bash
bash scripts/runtime/run_p10_rov_impact_once.sh \
  --mode rib_snapshot \
  --routes data/bgp/p10_route_tables/routeviews2_20260101T000000Z/routes.jsonl \
  --vrp probe-cd=data/probe/live_vrp_snapshots/probe-cd/latest_normalized_vrp.jsonl \
  --metadata probe-cd=data/probe/live_vrp_snapshots/probe-cd/latest_metadata.json \
  --vrp probe-sg=data/probe/remote_snapshots/probe-sg/latest_normalized_vrp.jsonl \
  --metadata probe-sg=data/probe/remote_snapshots/probe-sg/latest_metadata.json \
  --vrp probe-k02=data/probe/remote_snapshots/probe-k02/latest_normalized_vrp.jsonl \
  --metadata probe-k02=data/probe/remote_snapshots/probe-k02/latest_metadata.json \
  --p8-run-dir data/probe/cross_probe_pipeline/<P8_PASS_RUN> \
  --out-dir data/probe/p10_rov_impact/routeviews2_20260101_smoke

cat data/probe/p10_rov_impact/routeviews2_20260101_smoke/checks/P10_ROV_IMPACT_ACCEPTANCE.txt
```

Because this RIB is from `2026-01-01`, it is not suitable for formal
`2026-06-29` P8-window impact analysis. A stale-time exclusion from P10-A is
the correct behavior when the RIB time is too far from the VRP window.

## CD2 Notes

Install or expose `bgpdump` before running the builder:

```bash
bgpdump --help
```

If `bgpdump` is missing, P10-B1 still writes `routes.jsonl`,
`route_build_summary.json`, and `checks/P10_BGP_ROUTE_TABLE_ACCEPTANCE.txt`,
but the acceptance status is `FAIL` with `bgpdump_available=false`.

No MinIO, database, P8, P9, or P10-A behavior is modified by P10-B1.
