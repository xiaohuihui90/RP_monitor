from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class P0Paths:
    history_root: Path
    reports_dir: Path
    acceptance_dir: Path
    evidence_pack_root: Path
    m17_input_dir: Path

    @classmethod
    def from_defaults(cls) -> "P0Paths":
        base = Path("data/p3_collector/m245_three_layer_baseline")
        return cls(
            history_root=base / "history",
            reports_dir=base / "reports",
            acceptance_dir=base / "p0_acceptance",
            evidence_pack_root=base / "evidence_packs",
            m17_input_dir=base / "m17_vrp_entry_diff_inputs",
        )


def ensure_p0_dirs(paths: P0Paths) -> None:
    paths.reports_dir.mkdir(parents=True, exist_ok=True)
    paths.acceptance_dir.mkdir(parents=True, exist_ok=True)
    paths.evidence_pack_root.mkdir(parents=True, exist_ok=True)
    paths.m17_input_dir.mkdir(parents=True, exist_ok=True)
