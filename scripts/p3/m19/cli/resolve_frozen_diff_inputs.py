#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                obj["_line_no"] = line_no
                yield obj


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def resolve_cas_abs_path(m18_run_dir: Path, cas_path: str | None) -> Path | None:
    if not cas_path:
        return None

    p = Path(str(cas_path)).expanduser()

    if p.is_absolute():
        return p

    return m18_run_dir / p


def safe_link_or_copy(src: Path, dst: Path, mode: str) -> str:
    dst.parent.mkdir(parents=True, exist_ok=True)

    if dst.exists() or dst.is_symlink():
        dst.unlink()

    if mode == "copy":
        dst.write_bytes(src.read_bytes())
        return "copied"

    rel = os.path.relpath(src, start=dst.parent)
    os.symlink(rel, dst)
    return "symlinked"


def decide_resolver_status(row: Dict[str, Any], probe_inputs: Dict[str, Any]) -> str:
    missing = [
        probe for probe, info in probe_inputs.items()
        if not info.get("exists")
    ]

    existing = [
        probe for probe, info in probe_inputs.items()
        if info.get("exists")
    ]

    if missing:
        return "missing_cas_file"

    if row.get("semantic_diff_required") is True:
        return "ready" if len(existing) >= 2 else "partial_ready"

    if row.get("raw_hash_status") == "single_probe_only":
        return "single_probe_ready_no_cross_diff"

    return "no_diff_required"


def build_manifest(row: Dict[str, Any], run_dir: Path, m18_run_dir: Path, link_mode: str) -> Dict[str, Any]:
    object_diff_id = row.get("object_diff_id") or "unknown_object_diff_id"
    workspace = run_dir / "diff_inputs" / object_diff_id
    workspace.mkdir(parents=True, exist_ok=True)

    probe_values = row.get("probe_values") or {}
    probe_inputs = {}
    link_actions = []
    warnings = []

    for probe, value in sorted(probe_values.items()):
        raw_sha256 = value.get("raw_sha256")
        cas_path = value.get("cas_path")
        cas_abs = resolve_cas_abs_path(m18_run_dir, cas_path)

        exists = bool(cas_abs and cas_abs.exists() and cas_abs.is_file())

        dst_name = f"{probe}.obj"
        dst_path = workspace / dst_name

        action = "not_linked"

        if exists and cas_abs:
            try:
                action = safe_link_or_copy(cas_abs, dst_path, link_mode)
            except Exception as exc:
                exists = False
                action = "link_or_copy_failed"
                warnings.append(f"{probe}: {exc}")

        probe_inputs[probe] = {
            "raw_sha256": raw_sha256,
            "raw_size_bytes": value.get("raw_size_bytes"),
            "cas_path": cas_path,
            "cas_abs_path": str(cas_abs) if cas_abs else None,
            "exists": exists,
            "diff_input_path": dst_name if exists else None,
            "link_action": action,
            "recover_status": value.get("recover_status"),
        }

        link_actions.append(action)

    resolver_status = decide_resolver_status(row, probe_inputs)

    manifest = {
        "schema": "s3.m19.diff_input_manifest.v1",
        "created_at_utc": utc_now_iso(),
        "object_diff_id": object_diff_id,
        "identity_key": row.get("identity_key"),
        "canonical_uri": row.get("canonical_uri"),
        "object_uri": row.get("object_uri"),
        "object_type": row.get("object_type"),
        "object_family": row.get("object_family"),
        "raw_hash_status": row.get("raw_hash_status"),
        "diff_candidate_type": row.get("diff_candidate_type"),
        "semantic_diff_required": row.get("semantic_diff_required"),
        "semantic_diff_status": row.get("semantic_diff_status"),
        "coverage_scope": row.get("coverage_scope"),
        "probe_inputs": probe_inputs,
        "resolver_status": resolver_status,
        "workspace": str(workspace),
        "manifest_path": str(workspace / "diff_input_manifest.json"),
        "link_mode": link_mode,
        "link_actions": link_actions,
        "warnings": warnings,
    }

    write_json(workspace / "diff_input_manifest.json", manifest)

    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="M19-C frozen raw bytes diff input resolver")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--m18-run-dir", required=True)
    parser.add_argument("--object-diff-index", required=True)
    parser.add_argument("--link-mode", choices=["symlink", "copy"], default="symlink")
    args = parser.parse_args()

    run_dir = Path(args.run_dir).expanduser().resolve()
    m18_run_dir = Path(args.m18_run_dir).expanduser().resolve()
    object_diff_index = Path(args.object_diff_index).expanduser().resolve()

    outputs_dir = run_dir / "outputs"
    checks_dir = run_dir / "checks"
    outputs_dir.mkdir(parents=True, exist_ok=True)
    checks_dir.mkdir(parents=True, exist_ok=True)

    rows = list(read_jsonl(object_diff_index))
    manifests = [
        build_manifest(row, run_dir, m18_run_dir, args.link_mode)
        for row in rows
    ]

    by_resolver_status = Counter(m["resolver_status"] for m in manifests)
    by_raw_hash_status = Counter(m.get("raw_hash_status") for m in manifests)
    by_object_type = Counter(m.get("object_type") or "unknown" for m in manifests)

    semantic_required_count = sum(1 for m in manifests if m.get("semantic_diff_required") is True)
    missing_cas_file_count = sum(1 for m in manifests if m.get("resolver_status") == "missing_cas_file")
    ready_count = sum(1 for m in manifests if m.get("resolver_status") in {"ready", "no_diff_required", "single_probe_ready_no_cross_diff"})

    summary_path = outputs_dir / "M19C_diff_input_resolver_summary.json"
    check_path = checks_dir / "M19C_diff_input_resolver.txt"

    status = "PASS" if len(manifests) == len(rows) and missing_cas_file_count == 0 else "FAIL"

    summary = {
        "schema": "s3.m19c.diff_input_resolver_summary.v1",
        "status": status,
        "created_at_utc": utc_now_iso(),
        "run_dir": str(run_dir),
        "m18_run_dir": str(m18_run_dir),
        "object_diff_index": str(object_diff_index),
        "object_diff_record_count": len(rows),
        "diff_input_manifest_count": len(manifests),
        "semantic_diff_required_count": semantic_required_count,
        "missing_cas_file_count": missing_cas_file_count,
        "ready_or_no_diff_count": ready_count,
        "by_resolver_status": dict(by_resolver_status),
        "by_raw_hash_status": dict(by_raw_hash_status),
        "by_object_type": dict(by_object_type),
        "diff_inputs_dir": str(run_dir / "diff_inputs"),
        "link_mode": args.link_mode,
        "important_boundary": [
            "M19-C resolves frozen raw byte inputs from M18 CAS.",
            "Current data has no raw hash divergence, so semantic diff may be not required.",
            "This is recoverable-subset, not full raw-byte coverage."
        ],
    }

    write_json(summary_path, summary)

    text = "\n".join([
        f"M19C_DIFF_INPUT_RESOLVER={status}",
        "",
        "scope = frozen_raw_bytes_diff_input_resolver",
        f"object_diff_record_count = {len(rows)}",
        f"diff_input_manifest_count = {len(manifests)}",
        f"semantic_diff_required_count = {semantic_required_count}",
        f"missing_cas_file_count = {missing_cas_file_count}",
        f"ready_or_no_diff_count = {ready_count}",
        f"by_resolver_status = {dict(by_resolver_status)}",
        f"by_raw_hash_status = {dict(by_raw_hash_status)}",
        f"by_object_type = {dict(by_object_type)}",
        f"link_mode = {args.link_mode}",
        "",
        f"diff_inputs_dir = {run_dir / 'diff_inputs'}",
        f"summary_path = {summary_path}",
        "",
        "important_boundary = M19-C uses M18 recoverable-subset CAS only.",
    ]) + "\n"

    check_path.write_text(text, encoding="utf-8")
    print(text)

    return 0 if status == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
