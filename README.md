# RP_monitor

Curated scripts for the RPKI multi-view monitoring and attribution prototype.

## Scope

This repository contains selected engineering scripts for:

1. VRP output export, upload, normalization and pairwise diff.
2. Object-layer snapshot export, upload and comparison.
3. Announced-view collection and group-level comparison.
4. Two-layer and three-layer attribution gate prototypes.
5. Evidence-oriented closeout workflows.

## Current design model

The prototype follows a three-layer RPKI view model:

- L1: Announced view
  - RRDP notification/session/serial/digest/snapshot/delta chain.
- L2: Object view
  - Object inventory, active manifest records, object roots.
- L3: Validation output view
  - VRP output, canonical roots, pairwise diff.

The attribution logic follows:

1. Compare within each layer first.
2. Map differences across layers second.
3. Use same-window grouping to avoid temporal false attribution.
4. Block validator-only E4 attribution when lower-layer divergence is observed.

## Important safety note

This repository intentionally excludes:

- runtime data,
- logs,
- VRP raw JSON,
- object snapshots,
- evidence archives,
- private config files,
- local `.env` files,
- validator caches.

Configuration files should be created from local templates and should not contain secrets.
