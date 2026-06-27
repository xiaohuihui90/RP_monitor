# P3 Cross Probe Persistence Analyzer

P3 analyzes a sequence of P2 cross-probe VRP diff runs and separates short-lived
cross-probe differences from persistent view divergence. It is intentionally an
offline analyzer. It does not change the A-E runners, P1 deployment scripts, or
the P2 cross-probe diff engine.

P3 does not make root-cause claims. Every emitted record keeps:

- `causal_claim_allowed=false`
- `root_cause_confirmed=false`

## Inputs

P3 accepts either explicit P2 run directories or a root directory to scan:

```bash
python probe/analyze_cross_probe_persistence.py \
  --p2-run-dir data/probe/p2_cross_probe/window_1 \
  --p2-run-dir data/probe/p2_cross_probe/window_2 \
  --out-dir data/probe/p3_cross_window/probe-cd_probe-sg/latest
```

or:

```bash
python probe/analyze_cross_probe_persistence.py \
  --p2-root data/probe/p2_cross_probe \
  --min-consecutive 3 \
  --max-skew-sec 600 \
  --out-dir data/probe/p3_cross_window/latest
```

Each P2 run directory must contain:

- `cross_probe_summary.json`
- `candidate_events.jsonl`

Only windows with `window_quality=OK` and
`capture_time_skew_sec <= --max-skew-sec` are accepted. Bad or skewed windows
are recorded in `summary.json` under `skipped_windows` and do not contribute to
persistence classification.

## Classification

P3 tracks same-direction differences by:

```text
vrp_key + missing_probes
```

The primary VRP key remains:

```text
(tal, asn, prefix, max_length)
```

Classifications:

- `SINGLE_WINDOW_TRANSIENT`: observed in one accepted window only.
- `PROPAGATION_TRANSIENT`: observed in multiple windows but below
  `--min-consecutive`.
- `PERSISTENT_VIEW_DIVERGENCE`: observed for at least `--min-consecutive`
  consecutive accepted windows.
- `DIRECTION_FLAPPING`: the same `vrp_key` appears with multiple
  `missing_probes` directions across accepted windows.

For each record P3 emits first seen window, last seen window, consecutive window
count, total window count, recovery window/time when observed, present/missing
probe sets, and compact evidence windows.

If `source_uri` is absent or empty, P3 does not promote evidence. Records remain
pattern-only evidence.

## Semantic Divergence

P3 also checks semantic set divergence from P2 candidate events:

- `ORIGIN_SET_DIVERGENCE`: for each `(tal, prefix, max_length)`, compare each
  probe's ASN set.
- `MAX_LENGTH_SET_DIVERGENCE`: for each `(tal, asn, prefix)`, compare each
  probe's maxLength set.

These outputs are still observational only and do not imply cause.

## Outputs

The output directory contains:

- `persistent_events.jsonl`
- `transient_events.jsonl`
- `semantic_divergences.jsonl`
- `summary.json`
- `summary.csv`
- `checks/P3_CROSS_WINDOW_PERSISTENCE_ACCEPTANCE.txt`

`summary.json` includes accepted/skipped window counts, input event count,
classification distribution, semantic type distribution, TAL distribution, and
output paths.

## Local Acceptance

Run syntax checks:

```bash
cd /path/to/RP_monitor
python -m py_compile probe/analyze_cross_probe_persistence.py
python probe/analyze_cross_probe_persistence.py --help
```

Run the built-in synthetic self-test:

```bash
rm -rf /tmp/p3_cross_window_self_test
python probe/analyze_cross_probe_persistence.py \
  --self-test \
  --out-dir /tmp/p3_cross_window_self_test

cat /tmp/p3_cross_window_self_test/checks/P3_CROSS_WINDOW_PERSISTENCE_ACCEPTANCE.txt
python -m json.tool /tmp/p3_cross_window_self_test/summary.json
head -n 5 /tmp/p3_cross_window_self_test/persistent_events.jsonl
head -n 5 /tmp/p3_cross_window_self_test/transient_events.jsonl
head -n 5 /tmp/p3_cross_window_self_test/semantic_divergences.jsonl
```

The self-test covers:

- persistent missing across consecutive windows;
- single-window transient recovery;
- propagation transient below the persistence threshold;
- direction flapping;
- ASN origin set divergence;
- maxLength set divergence;
- bad/skewed window filtering.

## CD2 Example

```bash
cd /path/to/RP_monitor

python probe/analyze_cross_probe_persistence.py \
  --p2-root data/probe/p2_cross_probe \
  --min-consecutive 3 \
  --max-skew-sec 600 \
  --out-dir data/probe/p3_cross_window/$(date -u +%Y%m%dT%H%M%SZ)
```

P3 is not currently wired into cron. Keep it as an explicit analysis step until
the cross-probe P2 collection cadence is stable.
