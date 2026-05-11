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


def pick_bool(obj: dict[str, Any], keys: list[str], default: bool | None = None) -> bool | None:
    for key in keys:
        if key in obj:
            v = obj[key]
            if isinstance(v, bool):
                return v
            if isinstance(v, str):
                if v.lower() in {"true", "yes", "pass", "aligned"}:
                    return True
                if v.lower() in {"false", "no", "blocked", "not_aligned"}:
                    return False
    return default


def flatten_dicts(x: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    def walk(v: Any) -> None:
        if isinstance(v, dict):
            out.append(v)
            for vv in v.values():
                walk(vv)
        elif isinstance(v, list):
            for vv in v:
                walk(vv)

    walk(x)
    return out


def extract_validator_context(raw: dict[str, Any]) -> dict[str, Any]:
    dicts = flatten_dicts(raw)

    fields = {
        "validator_type_aligned": None,
        "validator_version_aligned": None,
        "config_fingerprint_aligned": None,
        "stable_config_fingerprint_aligned": None,
        "runtime_process_fingerprint_aligned": None,
        "tal_set_aligned": None,
        "fallback_policy_aligned": None,
        "local_filter_policy_aligned": None,
        "refresh_interval_aligned": None,
    }

    for name in list(fields):
        for d in dicts:
            v = pick_bool(d, [name])
            if v is not None:
                fields[name] = v
                break

    hard_blockers = []

    if fields["validator_type_aligned"] is False:
        hard_blockers.append("validator_type_not_aligned")
    if fields["validator_version_aligned"] is False:
        hard_blockers.append("validator_version_not_aligned")
    if fields["config_fingerprint_aligned"] is False:
        hard_blockers.append("config_fingerprint_not_aligned")
    if fields["stable_config_fingerprint_aligned"] is False:
        hard_blockers.append("stable_config_fingerprint_not_aligned")
    if fields["tal_set_aligned"] is False:
        hard_blockers.append("tal_set_not_aligned")
    if fields["fallback_policy_aligned"] is False:
        hard_blockers.append("fallback_policy_not_aligned")
    if fields["local_filter_policy_aligned"] is False:
        hard_blockers.append("local_filter_policy_not_aligned")

    warnings = []
    if fields["runtime_process_fingerprint_aligned"] is False:
        warnings.append("runtime_process_fingerprint_not_aligned_diagnostic")

    unknowns = [k for k, v in fields.items() if v is None]

    aligned_for_confirmed = not hard_blockers and not unknowns

    return {
        "available": True,
        **fields,
        "validator_environment_aligned_for_confirmed": aligned_for_confirmed,
        "hard_blockers": hard_blockers,
        "warnings": warnings,
        "unknown_fields": unknowns,
        "source_schema": raw.get("schema"),
        "source": raw.get("source"),
    }


def decide_with_validator(previous: dict[str, Any], validator_ctx: dict[str, Any]) -> tuple[str, str, bool, list[str], list[str]]:
    prev_status = previous.get("final_status")
    prev_e4 = previous.get("e4_status")
    prev_confirmed = bool(previous.get("confirmed_allowed"))

    blockers = list(previous.get("blockers", []))
    warnings = list(previous.get("warnings", []))

    for w in validator_ctx.get("warnings", []):
        if w not in warnings:
            warnings.append(w)

    if validator_ctx.get("unknown_fields"):
        msg = "validator_config_context_has_unknown_fields"
        if msg not in warnings:
            warnings.append(msg)

    # Object-layer version skew has higher priority than validator drift.
    if prev_status == "not_e4_object_layer_version_skew":
        if validator_ctx.get("hard_blockers"):
            warnings.append("validator_environment_drift_observed_but_object_layer_version_skew_has_priority")
        return prev_status, prev_e4 or "not_e4", False, blockers, warnings

    if not validator_ctx.get("validator_environment_aligned_for_confirmed"):
        for b in validator_ctx.get("hard_blockers", []):
            if b not in blockers:
                blockers.append(b)
        return "blocked_validator_environment_drift", "blocked", False, blockers, warnings

    return prev_status or "blocked_unknown", prev_e4 or "blocked", prev_confirmed, blockers, warnings


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def update_sha256s(run_dir: Path) -> None:
    out = run_dir / "checks" / "SHA256SUMS.txt"
    rows = []
    for p in sorted(run_dir.rglob("*")):
        if p.is_file() and p != out:
            rows.append((sha256_file(p), str(p.relative_to(run_dir))))
    out.write_text("".join(f"{digest}  {rel}\n" for digest, rel in rows), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="M14-C attach validator config context")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--validator-config-context", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir).resolve()
    ctx_path = Path(args.validator_config_context).resolve()

    prev_path = run_dir / "verdicts" / "final_verdict_m14.json"
    if not prev_path.exists():
        raise FileNotFoundError(prev_path)
    if not ctx_path.exists():
        raise FileNotFoundError(ctx_path)

    inputs_dir = run_dir / "inputs"
    verdicts_dir = run_dir / "verdicts"
    checks_dir = run_dir / "checks"
    inputs_dir.mkdir(parents=True, exist_ok=True)
    verdicts_dir.mkdir(parents=True, exist_ok=True)
    checks_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy2(ctx_path, inputs_dir / "validator_config_context_ref.json")

    previous = read_json(prev_path)
    raw_ctx = read_json(ctx_path)
    validator_ctx = extract_validator_context(raw_ctx)

    final_status, e4_status, confirmed_allowed, blockers, warnings = decide_with_validator(previous, validator_ctx)

    previous["m14_substage"] = "M14-C"
    previous["updated_at_utc"] = utc_now()
    previous["final_status"] = final_status
    previous["e4_status"] = e4_status
    previous["confirmed_allowed"] = confirmed_allowed
    previous["blockers"] = blockers
    previous["warnings"] = warnings
    previous.setdefault("context", {})
    previous["context"]["validator_config"] = validator_ctx
    previous.setdefault("gating", {})
    previous["gating"]["G3_validator_environment"] = (
        "pass"
        if validator_ctx.get("validator_environment_aligned_for_confirmed")
        else "blocked_or_warning"
    )
    previous["gating"]["G4_final_after_validator_context"] = final_status

    basis = previous.setdefault("evidence_basis", [])
    if "inputs/validator_config_context_ref.json" not in basis:
        basis.append("inputs/validator_config_context_ref.json")

    recs = previous.setdefault("recommendations", [])
    if not validator_ctx.get("validator_environment_aligned_for_confirmed"):
        recs.append("Align validator version/config/TAL/policy before allowing E4 confirmed.")

    write_json(prev_path, previous)

    text = f"""M14C_VALIDATOR_CONTEXT_JOIN=DONE

run_id = {run_dir.name}
run_dir = {run_dir}

final_status = {final_status}
e4_status = {e4_status}
confirmed_allowed = {confirmed_allowed}

validator_context_available = {validator_ctx.get("available")}
validator_environment_aligned_for_confirmed = {validator_ctx.get("validator_environment_aligned_for_confirmed")}
validator_type_aligned = {validator_ctx.get("validator_type_aligned")}
validator_version_aligned = {validator_ctx.get("validator_version_aligned")}
config_fingerprint_aligned = {validator_ctx.get("config_fingerprint_aligned")}
stable_config_fingerprint_aligned = {validator_ctx.get("stable_config_fingerprint_aligned")}
tal_set_aligned = {validator_ctx.get("tal_set_aligned")}
fallback_policy_aligned = {validator_ctx.get("fallback_policy_aligned")}
local_filter_policy_aligned = {validator_ctx.get("local_filter_policy_aligned")}
refresh_interval_aligned = {validator_ctx.get("refresh_interval_aligned")}

hard_blockers = {validator_ctx.get("hard_blockers")}
warnings = {warnings}

priority_interpretation:
If object-layer version skew is already proven, M14 keeps not_e4_object_layer_version_skew as the final status.
Validator environment drift is recorded as warning/context for this run and will block E4 confirmed in future non-object-skew cases.
"""
    (verdicts_dir / "99_m14_validator_context_verdict.txt").write_text(text, encoding="utf-8")

    acceptance_ok = (
        (final_status == "not_e4_object_layer_version_skew" and e4_status == "not_e4")
        or final_status == "blocked_validator_environment_drift"
        or validator_ctx.get("validator_environment_aligned_for_confirmed") is True
    )

    acceptance = f"""M14C_VALIDATOR_CONTEXT_JOIN=DONE

run_id = {run_dir.name}
validator_context_used = True
validator_environment_aligned_for_confirmed = {validator_ctx.get("validator_environment_aligned_for_confirmed")}
hard_blockers = {validator_ctx.get("hard_blockers")}

final_status = {final_status}
e4_status = {e4_status}
confirmed_allowed = {confirmed_allowed}

object_skew_priority_preserved = {final_status == "not_e4_object_layer_version_skew" and e4_status == "not_e4"}
m14c_acceptance = {acceptance_ok}

outputs:
  {prev_path}
  {verdicts_dir / "99_m14_validator_context_verdict.txt"}
  {inputs_dir / "validator_config_context_ref.json"}
"""
    (checks_dir / "M14C_acceptance_check.txt").write_text(acceptance, encoding="utf-8")

    update_sha256s(run_dir)

    print(json.dumps({
        "status": "done",
        "run_id": run_dir.name,
        "final_status": final_status,
        "e4_status": e4_status,
        "confirmed_allowed": confirmed_allowed,
        "validator_environment_aligned_for_confirmed": validator_ctx.get("validator_environment_aligned_for_confirmed"),
        "hard_blockers": validator_ctx.get("hard_blockers"),
        "m14c_acceptance": acceptance_ok,
        "acceptance_check": str(checks_dir / "M14C_acceptance_check.txt"),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
