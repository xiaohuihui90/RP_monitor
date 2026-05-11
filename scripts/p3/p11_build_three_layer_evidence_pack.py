#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def copy_required(src: Path, dst: Path, blockers: list[str]) -> bool:
    if not src.exists() or not src.is_file():
        blockers.append(f"missing_required:{src}")
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return True


def copy_optional(src: Path, dst: Path, warnings: list[str]) -> bool:
    if not src.exists() or not src.is_file():
        warnings.append(f"missing_optional:{src}")
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return True


def main() -> None:
    ap = argparse.ArgumentParser(description="Build P11 three-layer evidence pack")

    ap.add_argument("--group-id", required=True)
    ap.add_argument("--out-dir", required=True)

    ap.add_argument("--announced-view-group-manifest", required=True)
    ap.add_argument("--announced-view-pairwise-diff", required=True)
    ap.add_argument("--p11-c-acceptance", required=True)

    ap.add_argument("--object-joint-group-manifest", required=True)
    ap.add_argument("--object-layer-verdict", required=True)
    ap.add_argument("--object-layer-summary", required=True)

    ap.add_argument("--object-inventory-pairwise-diff", default="")
    ap.add_argument("--active-manifest-pairwise-diff", default="")

    ap.add_argument("--vrp-group-manifest", required=True)
    ap.add_argument("--vrp-layer-diff-manifest", required=True)
    ap.add_argument("--vrp-summary", required=True)
    ap.add_argument("--vrp-pairwise-diff", required=True)

    ap.add_argument("--p10-final-verdict", required=True)

    ap.add_argument("--three-layer-final-verdict", required=True)
    ap.add_argument("--three-layer-summary", required=True)
    ap.add_argument("--p11-d-acceptance", required=True)

    args = ap.parse_args()

    group_id = args.group_id
    out_dir = Path(args.out_dir)

    checks_dir = out_dir / "checks"
    manifests_dir = out_dir / "manifests"
    outputs_dir = out_dir / "outputs"
    evidence_dir = out_dir / "evidence"

    for d in [checks_dir, manifests_dir, outputs_dir, evidence_dir]:
        d.mkdir(parents=True, exist_ok=True)

    blockers: list[str] = []
    warnings: list[str] = []

    pack_name = f"{group_id}_p11_three_layer_joint_attribution_evidence"
    pack_root = evidence_dir / pack_name

    if pack_root.exists():
        shutil.rmtree(pack_root)

    pack_root.mkdir(parents=True, exist_ok=True)

    required_files = {
        "01_announced_view_group_manifest.json": Path(args.announced_view_group_manifest),
        "02_announced_view_pairwise_diff.json": Path(args.announced_view_pairwise_diff),
        "03_p11_c_announced_view_group_acceptance.txt": Path(args.p11_c_acceptance),

        "04_object_joint_group_manifest.json": Path(args.object_joint_group_manifest),
        "05_object_layer_verdict.json": Path(args.object_layer_verdict),
        "06_object_layer_compare_summary.json": Path(args.object_layer_summary),

        "09_vrp_group_manifest.json": Path(args.vrp_group_manifest),
        "10_vrp_layer_diff_manifest.json": Path(args.vrp_layer_diff_manifest),
        "11_m14_vrp_summary.json": Path(args.vrp_summary),
        "12_m14_vrp_pairwise_diff.json": Path(args.vrp_pairwise_diff),

        "13_p10_final_joint_e4a_gate.json": Path(args.p10_final_verdict),

        "14_three_layer_final_verdict.json": Path(args.three_layer_final_verdict),
        "15_three_layer_summary.json": Path(args.three_layer_summary),
        "16_p11_d_three_layer_final_gate_acceptance.txt": Path(args.p11_d_acceptance),
    }

    optional_files = {}
    if args.object_inventory_pairwise_diff:
        optional_files["07_object_inventory_pairwise_diff.json"] = Path(args.object_inventory_pairwise_diff)
    if args.active_manifest_pairwise_diff:
        optional_files["08_active_manifest_pairwise_diff.json"] = Path(args.active_manifest_pairwise_diff)

    copied_required = {}
    for dst_name, src in required_files.items():
        ok = copy_required(src, pack_root / dst_name, blockers)
        copied_required[dst_name] = {
            "source": str(src),
            "included": ok,
        }

    copied_optional = {}
    for dst_name, src in optional_files.items():
        ok = copy_optional(src, pack_root / dst_name, warnings)
        copied_optional[dst_name] = {
            "source": str(src),
            "included": ok,
        }

    # Read final verdict for compact metadata.
    final_verdict = None
    final_verdict_path = Path(args.three_layer_final_verdict)
    if final_verdict_path.exists():
        final_verdict = read_json(final_verdict_path)

    evidence_index = {
        "schema": "s3.stage3.m15.p11_three_layer_evidence_index.v1",
        "created_at_utc": utc_now(),
        "snapshot_group_id": group_id,
        "evidence_pack_name": pack_name,
        "final_status": (final_verdict or {}).get("final_status"),
        "strict_three_layer_status": (final_verdict or {}).get("strict_three_layer_status"),
        "e4_status": (final_verdict or {}).get("e4_status"),
        "confirmed_allowed": (final_verdict or {}).get("confirmed_allowed"),
        "blocking_layer": (final_verdict or {}).get("blocking_layer"),
        "attribution_layer": (final_verdict or {}).get("attribution_layer"),
        "confidence": (final_verdict or {}).get("confidence"),
        "required_files": copied_required,
        "optional_files": copied_optional,
        "warnings": warnings,
        "blockers": blockers,
    }

    write_json(pack_root / "00_EVIDENCE_INDEX.json", evidence_index)

    # SHA256SUMS inside evidence directory.
    sha_lines = []
    for p in sorted(pack_root.iterdir()):
        if p.is_file() and p.name != "SHA256SUMS.txt":
            sha_lines.append(f"{sha256_file(p)}  {p.name}")

    (pack_root / "SHA256SUMS.txt").write_text(
        "\n".join(sha_lines) + "\n",
        encoding="utf-8",
    )

    # Tar evidence contents.
    tar_path = evidence_dir / f"{pack_name}.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tf:
        tf.add(pack_root, arcname=pack_root.name)

    tar_sha = sha256_file(tar_path)
    tar_sha_path = evidence_dir / f"{pack_name}.tar.gz.sha256"
    tar_sha_path.write_text(f"{tar_sha}  {tar_path.name}\n", encoding="utf-8")

    required_outputs_ok = len(blockers) == 0
    acceptance = required_outputs_ok and tar_path.exists() and tar_sha_path.exists()

    manifest = {
        "schema": "s3.stage3.m15.p11_a4_evidence_pack_manifest.v1",
        "created_at_utc": utc_now(),
        "snapshot_group_id": group_id,
        "p11_a4_id": out_dir.name,
        "p11_a4_dir": str(out_dir),
        "final_status": (final_verdict or {}).get("final_status"),
        "strict_three_layer_status": (final_verdict or {}).get("strict_three_layer_status"),
        "e4_status": (final_verdict or {}).get("e4_status"),
        "confirmed_allowed": (final_verdict or {}).get("confirmed_allowed"),
        "blocking_layer": (final_verdict or {}).get("blocking_layer"),
        "attribution_layer": (final_verdict or {}).get("attribution_layer"),
        "confidence": (final_verdict or {}).get("confidence"),
        "evidence_pack_dir": str(pack_root),
        "evidence_pack": str(tar_path),
        "evidence_pack_sha256": tar_sha,
        "evidence_pack_sha256_file": str(tar_sha_path),
        "evidence_index": str(pack_root / "00_EVIDENCE_INDEX.json"),
        "evidence_sha256sums": str(pack_root / "SHA256SUMS.txt"),
        "warnings": warnings,
        "blockers": blockers,
        "required_outputs_ok": required_outputs_ok,
        "P11_A4_acceptance": acceptance,
    }

    write_json(manifests_dir / "P11_A4_three_layer_evidence_pack_manifest.json", manifest)

    # Copy manifest into outputs for convenience.
    write_json(outputs_dir / "P11_A4_three_layer_evidence_pack_summary.json", manifest)

    acceptance_text = f"""P11_A4_THREE_LAYER_EVIDENCE_PACK=DONE

created_at_utc = {utc_now()}

snapshot_group_id = {group_id}

final_status = {(final_verdict or {}).get("final_status")}
strict_three_layer_status = {(final_verdict or {}).get("strict_three_layer_status")}
e4_status = {(final_verdict or {}).get("e4_status")}
confirmed_allowed = {(final_verdict or {}).get("confirmed_allowed")}
blocking_layer = {(final_verdict or {}).get("blocking_layer")}
attribution_layer = {(final_verdict or {}).get("attribution_layer")}
confidence = {(final_verdict or {}).get("confidence")}

required_outputs_ok = {required_outputs_ok}

warnings = {warnings}
blockers = {blockers}

evidence_pack:
  {tar_path}

evidence_pack_sha256:
  {tar_sha}

evidence_index:
  {pack_root / "00_EVIDENCE_INDEX.json"}

evidence_sha256sums:
  {pack_root / "SHA256SUMS.txt"}

runtime_changes:
  collector_main_service_restarted = False
  probe_restarted = False
  new_validator_installed = False
  bgp_data_loaded = False
  cron_enabled = False

next_batch:
  Batch 5 / A5 / P11 closeout

P11_A4_acceptance = {acceptance}
"""

    (checks_dir / "P11_A4_three_layer_evidence_pack_acceptance.txt").write_text(
        acceptance_text,
        encoding="utf-8",
    )

    print(acceptance_text)

    if not acceptance:
        raise SystemExit("[BLOCKED] P11-A4 evidence pack acceptance is False")


if __name__ == "__main__":
    main()
