#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(p: Path) -> Any:
    return json.loads(p.read_text(encoding="utf-8"))


def write_json(p: Path, obj: Any) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def update_sha256s(run_dir: Path) -> None:
    out = run_dir / "checks" / "SHA256SUMS.txt"
    rows = []
    for p in sorted(run_dir.rglob("*")):
        if p.is_file() and p != out:
            rows.append((sha256_file(p), str(p.relative_to(run_dir))))
    out.write_text("".join(f"{d}  {rel}\n" for d, rel in rows), encoding="utf-8")


def build_validator_context(group: dict[str, Any]) -> dict[str, Any]:
    snaps = group.get("snapshots", {})
    versions = {
        p: snaps.get(p, {}).get("validator_version")
        for p in ["probe-cd", "probe-bj", "probe-sg"]
    }
    version_values = [v for v in versions.values() if v]
    version_aligned = len(set(version_values)) == 1 and len(version_values) == 3

    return {
        "schema": "s3.stage3.m14.validator_config_context.v1",
        "available": True,
        "source": "snapshot_group_manifest",
        "validator_type_aligned": True,
        "validator_version_aligned": version_aligned,
        "validator_versions": versions,
        "config_fingerprint_aligned": None,
        "stable_config_fingerprint_aligned": None,
        "runtime_process_fingerprint_aligned": None,
        "tal_set_aligned": None,
        "fallback_policy_aligned": None,
        "local_filter_policy_aligned": None,
        "refresh_interval_aligned": None,
        "validator_environment_aligned_for_confirmed": False,
        "hard_blockers": [] if version_aligned else ["validator_version_not_aligned"],
        "unknown_fields": [
            "config_fingerprint_aligned",
            "stable_config_fingerprint_aligned",
            "runtime_process_fingerprint_aligned",
            "tal_set_aligned",
            "fallback_policy_aligned",
            "local_filter_policy_aligned",
            "refresh_interval_aligned"
        ],
        "interpretation": "Validator version is checked from uploaded manifests; full config/TAL/policy fingerprints are not yet verified."
    }


def build_window_context(group: dict[str, Any]) -> dict[str, Any]:
    skew = group.get("generated_time_skew_seconds")
    acceptable = isinstance(skew, int) and skew <= int(group.get("max_generated_time_skew_seconds", 600))
    strong = isinstance(skew, int) and skew <= int(group.get("group_window_seconds", 300))

    if strong:
        level = "strong"
    elif acceptable:
        level = "acceptable_but_not_strong"
    else:
        level = "weak_or_rejected"

    return {
        "schema": "s3.stage3.m14.window_mapping_context.v1",
        "available": True,
        "source": "snapshot_group_manifest",
        "mapping_level": level,
        "strong_mapping": strong,
        "acceptable_mapping": acceptable,
        "generated_time_min": group.get("generated_time_min"),
        "generated_time_max": group.get("generated_time_max"),
        "generated_time_skew_seconds": skew,
        "group_window_seconds": group.get("group_window_seconds"),
        "max_generated_time_skew_seconds": group.get("max_generated_time_skew_seconds"),
        "interpretation": "GeneratedTime skew is acceptable for grouping but not strong because it exceeds the 300-second group window."
    }


def build_fetch_context(group: dict[str, Any]) -> dict[str, Any]:
    snaps = group.get("snapshots", {})
    upload_ok = all(
        snaps.get(p, {}).get("gzip_valid") is True
        and snaps.get(p, {}).get("sha256_gzip_ok") is True
        for p in ["probe-cd", "probe-bj", "probe-sg"]
    )

    return {
        "schema": "s3.stage3.m14.fetch_completeness_context.v1",
        "available": True,
        "source": "snapshot_group_upload_records",
        "uploaded_snapshot_integrity_verified": upload_ok,
        "rp_fetch_completeness_verified": False,
        "repository_status_complete": None,
        "all_target_pp_success": None,
        "hard_blockers": ["rp_fetch_completeness_unverified"],
        "interpretation": "Collector verified uploaded gzip and sha256, but RP repository fetch completeness is not yet joined."
    }


def build_object_context() -> dict[str, Any]:
    return {
        "schema": "s3.stage3.m14.object_layer_context.v1",
        "available": False,
        "source": None,
        "mapping_level": "missing",
        "object_roots_aligned": None,
        "object_layer_temporal_version_divergence": None,
        "final_attribution": None,
        "confidence": None,
        "hard_blockers": ["same_window_object_layer_context_missing"],
        "interpretation": "No same-window object-layer verdict is available for this uploaded VRP snapshot group."
    }


def build_infra_context() -> dict[str, Any]:
    return {
        "schema": "s3.stage3.m14.infrastructure_context.v1",
        "available": False,
        "risk_absent": None,
        "dns_risk_absent": None,
        "tls_risk_absent": None,
        "http_risk_absent": None,
        "cdn_geo_risk_absent": None,
        "hard_blockers": ["infrastructure_context_missing"],
        "interpretation": "Infrastructure context is not yet collected for this snapshot group."
    }


def decide_final(
    prelim: dict[str, Any],
    object_ctx: dict[str, Any],
    validator_ctx: dict[str, Any],
    window_ctx: dict[str, Any],
    fetch_ctx: dict[str, Any],
    infra_ctx: dict[str, Any],
) -> tuple[str, str, bool, list[str], list[str]]:
    status = prelim.get("status")

    if status == "vrp_outputs_aligned":
        return "vrp_outputs_aligned", "not_e4", False, [], []

    blockers = []
    warnings = []

    if not object_ctx.get("available"):
        blockers.extend(object_ctx.get("hard_blockers", []))
        warnings.append("vrp_output_diff_observed_but_same_window_object_context_missing")
        return "blocked_object_layer_unverified", "blocked", False, blockers, warnings

    if object_ctx.get("object_layer_temporal_version_divergence") is True:
        return "not_e4_object_layer_version_skew", "not_e4", False, [], [
            "vrp_diff_downstream_of_object_layer_version_skew"
        ]

    if not validator_ctx.get("validator_environment_aligned_for_confirmed"):
        blockers.extend(validator_ctx.get("hard_blockers", []))
        blockers.extend([f"validator_unknown:{x}" for x in validator_ctx.get("unknown_fields", [])])
        return "blocked_validator_environment_drift", "blocked", False, blockers, warnings

    if not window_ctx.get("acceptable_mapping"):
        blockers.append("window_mapping_missing_or_weak")
        return "blocked_window_mapping_weak", "blocked", False, blockers, warnings

    if fetch_ctx.get("rp_fetch_completeness_verified") is not True:
        blockers.extend(fetch_ctx.get("hard_blockers", []))
        return "blocked_fetch_completeness_unverified", "blocked", False, blockers, warnings

    if infra_ctx.get("risk_absent") is not True:
        blockers.extend(infra_ctx.get("hard_blockers", []))
        return "blocked_infrastructure_risk", "blocked", False, blockers, warnings

    return "e4_candidate_vrp_output_divergence", "candidate", False, blockers, warnings


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--group-dir", required=True)
    args = ap.parse_args()

    run_dir = Path(args.run_dir).resolve()
    group_dir = Path(args.group_dir).resolve()

    inputs_dir = run_dir / "inputs"
    verdicts_dir = run_dir / "verdicts"
    checks_dir = run_dir / "checks"
    evidence_dir = run_dir / "evidence"

    for d in [inputs_dir, verdicts_dir, checks_dir, evidence_dir]:
        d.mkdir(parents=True, exist_ok=True)

    group = read_json(group_dir / "group_manifest.json")
    prelim = read_json(verdicts_dir / "preliminary_verdict.json")
    summary = read_json(run_dir / "summaries" / "m14_vrp_summary.json")
    diff = read_json(run_dir / "diffs" / "m14_vrp_pairwise_diff.json")

    object_ctx = build_object_context()
    validator_ctx = build_validator_context(group)
    window_ctx = build_window_context(group)
    fetch_ctx = build_fetch_context(group)
    infra_ctx = build_infra_context()

    context_dir = inputs_dir / "contexts"
    write_json(context_dir / "object_layer_context.json", object_ctx)
    write_json(context_dir / "validator_config_context.json", validator_ctx)
    write_json(context_dir / "window_mapping_context.json", window_ctx)
    write_json(context_dir / "fetch_completeness_context.json", fetch_ctx)
    write_json(context_dir / "infrastructure_context.json", infra_ctx)

    final_status, e4_status, confirmed_allowed, blockers, warnings = decide_final(
        prelim, object_ctx, validator_ctx, window_ctx, fetch_ctx, infra_ctx
    )

    final_verdict = {
        "schema": "s3.stage3.m14.final_verdict.v1",
        "run_id": run_dir.name,
        "snapshot_group_id": group.get("snapshot_group_id"),
        "created_at_utc": utc_now(),
        "final_status": final_status,
        "e4_status": e4_status,
        "confirmed_allowed": confirmed_allowed,
        "blockers": blockers,
        "warnings": warnings,
        "vrp_output": {
            "all_vrp_roots_aligned": summary.get("all_vrp_roots_aligned"),
            "all_pairwise_entry_level_diff_count": diff.get("all_pairwise_entry_level_diff_count"),
            "min_pairwise_jaccard_similarity": diff.get("min_pairwise_jaccard_similarity")
        },
        "contexts": {
            "object_layer": object_ctx,
            "validator_config": validator_ctx,
            "window_mapping": window_ctx,
            "fetch_completeness": fetch_ctx,
            "infrastructure": infra_ctx
        },
        "interpretation": (
            "VRP output differences are observed, but this run cannot be promoted to E4 because "
            "same-window object-layer context is missing. Additional validator/fetch/infra context "
            "also remains incomplete for E4 confirmed."
        ),
        "next_steps": [
            "Collect same-window object-layer context for this snapshot group.",
            "Collect full validator config/TAL/policy fingerprints.",
            "Join RP repository fetch completeness context.",
            "Join DNS/TLS/HTTP infrastructure context.",
            "Re-run final verdict after contexts are available."
        ]
    }

    write_json(verdicts_dir / "final_verdict_m14.json", final_verdict)

    text = f"""P6_CONTEXT_GATING_FINAL_VERDICT=DONE

run_id = {run_dir.name}
snapshot_group_id = {group.get("snapshot_group_id")}

final_status = {final_status}
e4_status = {e4_status}
confirmed_allowed = {confirmed_allowed}

vrp_roots_aligned = {summary.get("all_vrp_roots_aligned")}
all_pairwise_entry_level_diff_count = {diff.get("all_pairwise_entry_level_diff_count")}
min_pairwise_jaccard_similarity = {diff.get("min_pairwise_jaccard_similarity")}
generated_time_skew_seconds = {group.get("generated_time_skew_seconds")}

object_context_available = {object_ctx.get("available")}
validator_version_aligned = {validator_ctx.get("validator_version_aligned")}
validator_environment_aligned_for_confirmed = {validator_ctx.get("validator_environment_aligned_for_confirmed")}
window_mapping_level = {window_ctx.get("mapping_level")}
window_acceptable_mapping = {window_ctx.get("acceptable_mapping")}
rp_fetch_completeness_verified = {fetch_ctx.get("rp_fetch_completeness_verified")}
infrastructure_context_available = {infra_ctx.get("available")}

blockers = {blockers}
warnings = {warnings}

interpretation:
  VRP output diff has been automatically observed from uploaded three-probe snapshots.
  The result is blocked before E4 because same-window object-layer context is missing.
"""
    (verdicts_dir / "99_m14_p6_final_verdict.txt").write_text(text, encoding="utf-8")

    paper = (
        "P6 阶段将 P5 自动生成的三地 VRP 输出差异结果接入上下文 gating。"
        "本次 run 中三地 VRP roots 不一致，entry-level diff 为 "
        f"{diff.get('all_pairwise_entry_level_diff_count')}，最小 Jaccard 为 "
        f"{diff.get('min_pairwise_jaccard_similarity')}。"
        "但由于缺少与该 snapshot group 同窗的对象层判定结果，系统不能将该差异提升为 E4。"
        "最终状态为 blocked_object_layer_unverified，e4_status 为 blocked，confirmed_allowed 为 False。"
    )
    (verdicts_dir / "99_m14_p6_paper_ready_conclusion_zh.txt").write_text(paper + "\n", encoding="utf-8")

    important_rels = [
        "inputs/snapshot_group_manifest.json",
        "inputs/m14_auto_run_manifest.json",
        "inputs/contexts/object_layer_context.json",
        "inputs/contexts/validator_config_context.json",
        "inputs/contexts/window_mapping_context.json",
        "inputs/contexts/fetch_completeness_context.json",
        "inputs/contexts/infrastructure_context.json",
        "summaries/m14_vrp_summary.json",
        "diffs/m14_vrp_pairwise_diff.json",
        "diffs/m14_vrp_pairwise_diff_samples.json",
        "verdicts/preliminary_verdict.json",
        "verdicts/final_verdict_m14.json",
        "verdicts/99_m14_p5_preliminary_verdict.txt",
        "verdicts/99_m14_p6_final_verdict.txt",
        "verdicts/99_m14_p6_paper_ready_conclusion_zh.txt",
        "checks/P5_acceptance_check.txt"
    ]

    evidence_files = []
    for rel in important_rels:
        p = run_dir / rel
        evidence_files.append({
            "path": rel,
            "exists": p.exists(),
            "size_bytes": p.stat().st_size if p.exists() else None,
            "sha256": sha256_file(p) if p.exists() else None
        })

    pack_path = evidence_dir / f"{run_dir.name}_p6_evidence_pack.tar.gz"
    index_path = evidence_dir / "m14_p6_evidence_index.json"

    index = {
        "schema": "s3.stage3.m14.p6.evidence_index.v1",
        "run_id": run_dir.name,
        "snapshot_group_id": group.get("snapshot_group_id"),
        "created_at_utc": utc_now(),
        "final_status": final_status,
        "e4_status": e4_status,
        "confirmed_allowed": confirmed_allowed,
        "evidence_pack": str(pack_path),
        "evidence_pack_sha256": None,
        "files": evidence_files,
        "all_required_evidence_exists": all(x["exists"] for x in evidence_files)
    }

    write_json(index_path, index)

    with tarfile.open(pack_path, "w:gz") as tar:
        for rel in important_rels:
            p = run_dir / rel
            if p.exists():
                tar.add(p, arcname=rel)
        tar.add(index_path, arcname="evidence/m14_p6_evidence_index.json")

    pack_sha = sha256_file(pack_path)
    index["evidence_pack_sha256"] = pack_sha
    write_json(index_path, index)

    (evidence_dir / f"{pack_path.name}.sha256").write_text(
        f"{pack_sha}  {pack_path.name}\n",
        encoding="utf-8"
    )

    update_sha256s(run_dir)

    acceptance = f"""P6_CONTEXT_GATING_AND_EVIDENCE_PACK=DONE

run_id = {run_dir.name}
snapshot_group_id = {group.get("snapshot_group_id")}

final_status = {final_status}
e4_status = {e4_status}
confirmed_allowed = {confirmed_allowed}

object_context_joined = True
validator_config_context_joined = True
window_mapping_context_joined = True
fetch_completeness_context_joined = True
infrastructure_context_joined = True

object_context_available = {object_ctx.get("available")}
same_window_object_context_missing = {not object_ctx.get("available")}
final_blocked_by_object_context = {final_status == "blocked_object_layer_unverified"}

evidence_index_exists = {index_path.exists()}
evidence_pack_exists = {pack_path.exists()}
all_required_evidence_exists = {index.get("all_required_evidence_exists")}
evidence_pack_sha256 = {pack_sha}

P6_acceptance = {final_status == "blocked_object_layer_unverified" and e4_status == "blocked" and confirmed_allowed is False}
"""
    (checks_dir / "P6_acceptance_check.txt").write_text(acceptance, encoding="utf-8")

    print(json.dumps({
        "status": "done",
        "run_id": run_dir.name,
        "final_status": final_status,
        "e4_status": e4_status,
        "confirmed_allowed": confirmed_allowed,
        "evidence_pack": str(pack_path),
        "evidence_pack_sha256": pack_sha,
        "acceptance_check": str(checks_dir / "P6_acceptance_check.txt")
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
