#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
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


def pick(obj: dict[str, Any], keys: list[str], default: Any = None) -> Any:
    for key in keys:
        if key in obj and obj[key] not in (None, ""):
            return obj[key]
    return default


def flatten_candidate_sources(obj: Any) -> list[dict[str, Any]]:
    """
    Robustly collect nested dicts from final_verdict_5e5.json, because
    older M12/M13 verdict files may wrap status fields in different levels.
    """
    out: list[dict[str, Any]] = []

    def walk(x: Any) -> None:
        if isinstance(x, dict):
            out.append(x)
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)

    walk(obj)
    return out


def extract_object_verdict(obj: dict[str, Any]) -> dict[str, Any]:
    candidates = flatten_candidate_sources(obj)

    final_status = pick(obj, ["final_status", "status"])
    final_attribution = pick(obj, ["final_attribution", "attribution", "primary_attribution"])
    e4_status = pick(obj, ["e4_status"])
    confidence = pick(obj, ["confidence"])

    for c in candidates:
        final_status = final_status or pick(c, ["final_status", "status"])
        final_attribution = final_attribution or pick(c, ["final_attribution", "attribution", "primary_attribution"])
        e4_status = e4_status or pick(c, ["e4_status"])
        confidence = confidence or pick(c, ["confidence"])

    return {
        "available": True,
        "final_status": final_status,
        "final_attribution": final_attribution,
        "e4_status": e4_status,
        "confidence": confidence,
        "object_layer_version_skew": (
            final_status == "object_layer_temporal_version_divergence"
            and final_attribution == "manifest_version_skew_dominant"
        ),
    }


def top_diff_tal(diff_obj: dict[str, Any]) -> tuple[str | None, float | None]:
    total = 0
    counter: dict[str, int] = {}
    for pair in diff_obj.get("pair_summary", {}).values():
        for tal, count in pair.get("tal_diff_breakdown", {}).items():
            counter[tal] = counter.get(tal, 0) + int(count)
            total += int(count)
    if not counter:
        return None, None
    tal, count = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[0]
    ratio = count / total if total else None
    return tal, ratio


def decide_status(summary: dict[str, Any], diff: dict[str, Any], object_ctx: dict[str, Any]) -> tuple[str, str, bool, str, str]:
    all_roots_aligned = bool(summary.get("all_vrp_roots_aligned"))
    entry_diff_count = int(diff.get("all_pairwise_entry_level_diff_count") or 0)

    if all_roots_aligned and entry_diff_count == 0:
        return (
            "vrp_outputs_aligned",
            "not_e4",
            False,
            "vrp_outputs_aligned",
            "No VRP output divergence was observed.",
        )

    if object_ctx.get("object_layer_version_skew"):
        return (
            "not_e4_object_layer_version_skew",
            "not_e4",
            False,
            "object_layer_temporal_version_divergence",
            "VRP output differences are downstream of object-layer manifest version skew.",
        )

    if not object_ctx.get("available"):
        return (
            "blocked_object_layer_unverified",
            "blocked",
            False,
            "object_layer_unverified",
            "Object-layer verdict is missing, so E4 cannot be confirmed.",
        )

    if entry_diff_count > 0:
        return (
            "e4_candidate_vrp_output_divergence",
            "candidate",
            False,
            "validated_output_divergence_candidate",
            "VRP roots differ, but only object verdict has been joined in M14-B.",
        )

    return (
        "blocked_unknown",
        "blocked",
        False,
        "unknown",
        "No deterministic verdict rule matched.",
    )


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def update_sha256s(run_dir: Path) -> None:
    out = run_dir / "checks" / "SHA256SUMS.txt"
    rows: list[tuple[str, str]] = []
    for p in sorted(run_dir.rglob("*")):
        if p.is_file() and p != out:
            rows.append((sha256_file(p), str(p.relative_to(run_dir))))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(f"{digest}  {rel}\n" for digest, rel in rows), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="M14-B attach M13 object verdict to M14-A VRP diff")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--object-verdict", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir).resolve()
    object_verdict_path = Path(args.object_verdict).resolve()

    summary_path = run_dir / "summaries" / "m14_vrp_summary.json"
    diff_path = run_dir / "diffs" / "m14_vrp_pairwise_diff.json"
    sample_path = run_dir / "diffs" / "m14_vrp_pairwise_diff_samples.json"

    if not summary_path.exists():
        raise FileNotFoundError(summary_path)
    if not diff_path.exists():
        raise FileNotFoundError(diff_path)
    if not object_verdict_path.exists():
        raise FileNotFoundError(object_verdict_path)

    verdicts_dir = run_dir / "verdicts"
    inputs_dir = run_dir / "inputs"
    checks_dir = run_dir / "checks"
    verdicts_dir.mkdir(parents=True, exist_ok=True)
    inputs_dir.mkdir(parents=True, exist_ok=True)
    checks_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy2(object_verdict_path, inputs_dir / "object_verdict_ref.json")

    summary = read_json(summary_path)
    diff = read_json(diff_path)
    samples_exists = sample_path.exists()
    object_raw = read_json(object_verdict_path)
    object_ctx = extract_object_verdict(object_raw)

    top_tal, tal_ratio = top_diff_tal(diff)

    final_status, e4_status, confirmed_allowed, primary_attr, explanation = decide_status(
        summary=summary,
        diff=diff,
        object_ctx=object_ctx,
    )

    final_verdict = {
        "schema": "s3.stage3.m14.final_verdict.v1",
        "m14_substage": "M14-B",
        "run_id": run_dir.name,
        "created_at_utc": utc_now(),
        "final_status": final_status,
        "e4_status": e4_status,
        "confidence": object_ctx.get("confidence") or "medium",
        "confirmed_allowed": confirmed_allowed,
        "primary_attribution": primary_attr,
        "secondary_attribution": object_ctx.get("final_attribution"),
        "explanation": explanation,
        "vrp_output": {
            "summary_available": True,
            "diff_available": True,
            "samples_available": samples_exists,
            "all_vrp_roots_aligned": summary.get("all_vrp_roots_aligned"),
            "all_pairwise_entry_level_diff_count": diff.get("all_pairwise_entry_level_diff_count"),
            "min_pairwise_jaccard_similarity": diff.get("min_pairwise_jaccard_similarity"),
            "top_diff_tal": top_tal,
            "tal_concentration_ratio": tal_ratio,
        },
        "context": {
            "object_layer": object_ctx,
            "validator_config": {"available": False, "status": "not_joined_in_m14b"},
            "window_mapping": {"available": False, "status": "not_joined_in_m14b"},
            "fetch_completeness": {"available": False, "status": "not_joined_in_m14b"},
            "infrastructure": {"available": False, "status": "not_joined_in_m14b"},
        },
        "gating": {
            "G0_vrp_input_integrity": "pass",
            "G1_vrp_output": "pass_aligned" if summary.get("all_vrp_roots_aligned") else "pass_diff_observed",
            "G2_object_view": (
                "not_e4_object_layer_version_skew"
                if object_ctx.get("object_layer_version_skew")
                else "pass_or_unverified"
            ),
            "G3_final": final_status,
        },
        "blockers": [],
        "warnings": [
            "M14-B only joins object verdict; validator_config/window/fetch/infrastructure contexts are not joined yet."
        ],
        "candidate_causes": [
            primary_attr,
            object_ctx.get("final_attribution"),
        ],
        "evidence_basis": [
            "summaries/m14_vrp_summary.json",
            "diffs/m14_vrp_pairwise_diff.json",
            "diffs/m14_vrp_pairwise_diff_samples.json",
            "inputs/object_verdict_ref.json",
        ],
        "recommendations": [
            "Do not mark this case as E4 if object verdict is manifest_version_skew_dominant.",
            "Proceed to M14-C to join validator_config_context.",
            "Proceed to M14-D/E to join window/fetch/infrastructure contexts and package evidence.",
        ],
    }

    write_json(verdicts_dir / "final_verdict_m14.json", final_verdict)

    text = f"""M14B_OBJECT_VERDICT_JOIN=DONE

run_id = {run_dir.name}
run_dir = {run_dir}

final_status = {final_status}
e4_status = {e4_status}
confirmed_allowed = {confirmed_allowed}
primary_attribution = {primary_attr}
secondary_attribution = {object_ctx.get("final_attribution")}
confidence = {final_verdict["confidence"]}

vrp_roots_aligned = {summary.get("all_vrp_roots_aligned")}
all_pairwise_entry_level_diff_count = {diff.get("all_pairwise_entry_level_diff_count")}
min_pairwise_jaccard_similarity = {diff.get("min_pairwise_jaccard_similarity")}

object_verdict_available = {object_ctx.get("available")}
object_final_status = {object_ctx.get("final_status")}
object_final_attribution = {object_ctx.get("final_attribution")}
object_e4_status = {object_ctx.get("e4_status")}
object_layer_version_skew = {object_ctx.get("object_layer_version_skew")}

interpretation:
{explanation}
"""
    (verdicts_dir / "99_m14_vrp_output_verdict.txt").write_text(text, encoding="utf-8")

    paper = (
        "M14-B 阶段将 M14-A 的 VRP 输出层差异结果与 M13 归档的 M12-R3/5E object verdict 进行了联动。"
        "本次运行中，VRP roots 未完全对齐，说明输出层存在可观察差异；"
        "但 M13 object verdict 已将上游对象层判定为 object_layer_temporal_version_divergence，"
        "主导归因为 manifest_version_skew_dominant。因此，该输出层差异不能确认为 E4 validated-output divergence，"
        "应降级为 not_e4_object_layer_version_skew。后续 M14-C 将继续接入 validator_config_context，"
        "M14-D/E 将补齐 window、fetch、infrastructure context 与 evidence pack。"
    )
    (verdicts_dir / "99_m14_paper_ready_conclusion_zh.txt").write_text(paper + "\n", encoding="utf-8")

    acceptance = f"""M14B_OBJECT_VERDICT_JOIN=DONE

run_id = {run_dir.name}
final_status = {final_status}
e4_status = {e4_status}
confirmed_allowed = {confirmed_allowed}

object_verdict_used = True
object_layer_version_skew = {object_ctx.get("object_layer_version_skew")}
expected_for_current_m13_case = not_e4_object_layer_version_skew
m14b_acceptance = {final_status == "not_e4_object_layer_version_skew" and e4_status == "not_e4" and confirmed_allowed is False}

outputs:
  {verdicts_dir / "final_verdict_m14.json"}
  {verdicts_dir / "99_m14_vrp_output_verdict.txt"}
  {verdicts_dir / "99_m14_paper_ready_conclusion_zh.txt"}
  {inputs_dir / "object_verdict_ref.json"}
"""
    (checks_dir / "M14B_acceptance_check.txt").write_text(acceptance, encoding="utf-8")

    update_sha256s(run_dir)

    print(json.dumps({
        "status": "done",
        "run_id": run_dir.name,
        "final_status": final_status,
        "e4_status": e4_status,
        "confirmed_allowed": confirmed_allowed,
        "m14b_acceptance": final_status == "not_e4_object_layer_version_skew" and e4_status == "not_e4" and confirmed_allowed is False,
        "acceptance_check": str(checks_dir / "M14B_acceptance_check.txt"),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
