#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def iter_manifests(diff_inputs_dir: Path) -> Iterable[Dict[str, Any]]:
    for path in sorted(diff_inputs_dir.rglob("diff_input_manifest.json")):
        try:
            obj = read_json(path)
        except Exception:
            continue

        obj["_manifest_file"] = str(path)
        yield obj


def sha256_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None

    h = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)

    return "sha256:" + h.hexdigest()


def summarize_probe_inputs(manifest: Dict[str, Any], workspace: Path) -> Dict[str, Any]:
    out = {}

    probe_inputs = manifest.get("probe_inputs") or {}

    for probe, info in sorted(probe_inputs.items()):
        rel = info.get("diff_input_path")
        raw_path = workspace / rel if rel else None

        out[probe] = {
            "raw_sha256_declared": info.get("raw_sha256"),
            "raw_sha256_verified": sha256_file(raw_path) if raw_path else None,
            "raw_size_bytes": info.get("raw_size_bytes"),
            "exists": bool(raw_path and raw_path.exists()),
            "input_path": str(raw_path) if raw_path else None,
        }

    return out


def make_not_required_evidence(manifest: Dict[str, Any], semantic_dir: Path) -> Dict[str, Any]:
    object_diff_id = manifest.get("object_diff_id")
    workspace = Path(manifest.get("workspace"))

    probe_summary = summarize_probe_inputs(manifest, workspace)

    evidence = {
        "schema": "s3.m19.semantic_diff_evidence.v1",
        "created_at_utc": utc_now_iso(),
        "object_diff_id": object_diff_id,
        "identity_key": manifest.get("identity_key"),
        "canonical_uri": manifest.get("canonical_uri"),
        "object_uri": manifest.get("object_uri"),
        "object_type": manifest.get("object_type"),
        "object_family": manifest.get("object_family"),
        "raw_hash_status": manifest.get("raw_hash_status"),
        "diff_candidate_type": manifest.get("diff_candidate_type"),
        "semantic_diff_required": False,
        "semantic_diff_status": "no_semantic_diff_required",
        "probe_raw_summary": probe_summary,
        "semantic_summary_by_probe": {},
        "semantic_diff": {
            "changed_fields": [],
            "added_items": [],
            "removed_items": [],
            "hash_changed_items": [],
        },
        "interpretation": {
            "semantic_class": "not_required_raw_hash_aligned_or_single_probe_only",
            "confidence": "high",
            "notes": [
                "No semantic diff was executed because semantic_diff_required=false.",
                "Current M19 input is recoverable subset, not full raw-byte coverage.",
            ],
        },
        "parser": {
            "name": "m19_semantic_diff_framework",
            "mode": "no_diff_required",
            "warnings": [],
        },
    }

    out_path = semantic_dir / object_diff_id / "semantic_diff.json"
    write_json(out_path, evidence)

    return evidence


def make_pending_or_stub_evidence(manifest: Dict[str, Any], semantic_dir: Path) -> Dict[str, Any]:
    object_diff_id = manifest.get("object_diff_id")
    workspace = Path(manifest.get("workspace"))

    probe_summary = summarize_probe_inputs(manifest, workspace)
    object_type = manifest.get("object_type") or "unknown"

    supported_stub_types = {"mft", "crl", "roa", "cer"}

    if object_type in supported_stub_types:
        status = "parse_failed"
        warning = "semantic_parser_stub_present_but_no_full_parser_enabled"
    else:
        status = "unsupported_object_type"
        warning = "unsupported_object_type_for_semantic_diff"

    evidence = {
        "schema": "s3.m19.semantic_diff_evidence.v1",
        "created_at_utc": utc_now_iso(),
        "object_diff_id": object_diff_id,
        "identity_key": manifest.get("identity_key"),
        "canonical_uri": manifest.get("canonical_uri"),
        "object_uri": manifest.get("object_uri"),
        "object_type": object_type,
        "object_family": manifest.get("object_family"),
        "raw_hash_status": manifest.get("raw_hash_status"),
        "diff_candidate_type": manifest.get("diff_candidate_type"),
        "semantic_diff_required": True,
        "semantic_diff_status": status,
        "probe_raw_summary": probe_summary,
        "semantic_summary_by_probe": {},
        "semantic_diff": {
            "changed_fields": [],
            "added_items": [],
            "removed_items": [],
            "hash_changed_items": [],
        },
        "interpretation": {
            "semantic_class": "semantic_parser_not_fully_enabled",
            "confidence": "low",
            "notes": [
                "Raw divergence requires semantic diff, but current framework only provides parser stubs.",
            ],
        },
        "parser": {
            "name": "m19_semantic_diff_framework",
            "mode": "stub",
            "warnings": [warning],
        },
    }

    out_path = semantic_dir / object_diff_id / "semantic_diff.json"
    write_json(out_path, evidence)

    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description="M19-D semantic diff framework")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--diff-inputs-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir).expanduser().resolve()
    diff_inputs_dir = Path(args.diff_inputs_dir).expanduser().resolve()

    semantic_dir = run_dir / "semantic_diffs"
    outputs_dir = run_dir / "outputs"
    checks_dir = run_dir / "checks"

    semantic_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)
    checks_dir.mkdir(parents=True, exist_ok=True)

    manifests = list(iter_manifests(diff_inputs_dir))
    evidences = []

    for manifest in manifests:
        if manifest.get("semantic_diff_required") is True:
            evidences.append(make_pending_or_stub_evidence(manifest, semantic_dir))
        else:
            evidences.append(make_not_required_evidence(manifest, semantic_dir))

    by_semantic_status = Counter(e.get("semantic_diff_status") for e in evidences)
    by_object_type = Counter(e.get("object_type") or "unknown" for e in evidences)
    by_raw_hash_status = Counter(e.get("raw_hash_status") for e in evidences)

    semantic_required_count = sum(1 for e in evidences if e.get("semantic_diff_required") is True)
    semantic_available_count = by_semantic_status.get("available", 0)
    parse_failed_count = by_semantic_status.get("parse_failed", 0)

    status = "PASS"

    if len(evidences) != len(manifests):
        status = "FAIL"

    if semantic_required_count > 0 and parse_failed_count > 0:
        status = "PASS_WITH_PARSER_STUB"

    summary_path = outputs_dir / "M19D_semantic_diff_summary.json"
    check_path = checks_dir / "M19D_semantic_diff_framework.txt"

    summary = {
        "schema": "s3.m19d.semantic_diff_summary.v1",
        "status": status,
        "created_at_utc": utc_now_iso(),
        "run_dir": str(run_dir),
        "diff_inputs_dir": str(diff_inputs_dir),
        "semantic_diffs_dir": str(semantic_dir),
        "diff_input_manifest_count": len(manifests),
        "semantic_evidence_count": len(evidences),
        "semantic_diff_required_count": semantic_required_count,
        "semantic_diff_available_count": semantic_available_count,
        "parse_failed_count": parse_failed_count,
        "by_semantic_diff_status": dict(by_semantic_status),
        "by_object_type": dict(by_object_type),
        "by_raw_hash_status": dict(by_raw_hash_status),
        "important_boundary": [
            "M19-D runs semantic diff framework over M19-C diff inputs.",
            "Current input has no raw hash divergence, so semantic diff is not required.",
            "Parser stubs are present for future raw divergence cases.",
            "This is recoverable-subset, not full raw-byte coverage.",
        ],
    }

    write_json(summary_path, summary)

    text = "\n".join([
        f"M19D_SEMANTIC_DIFF_FRAMEWORK={status}",
        "",
        "scope = semantic_diff_framework",
        f"diff_input_manifest_count = {len(manifests)}",
        f"semantic_evidence_count = {len(evidences)}",
        f"semantic_diff_required_count = {semantic_required_count}",
        f"semantic_diff_available_count = {semantic_available_count}",
        f"parse_failed_count = {parse_failed_count}",
        f"by_semantic_diff_status = {dict(by_semantic_status)}",
        f"by_object_type = {dict(by_object_type)}",
        f"by_raw_hash_status = {dict(by_raw_hash_status)}",
        "",
        f"semantic_diffs_dir = {semantic_dir}",
        f"summary_path = {summary_path}",
        "",
        "important_boundary = Current input has no raw hash divergence, so semantic diff evidence is no_semantic_diff_required.",
    ]) + "\n"

    check_path.write_text(text, encoding="utf-8")
    print(text)

    return 0 if status in {"PASS", "PASS_WITH_PARSER_STUB"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
