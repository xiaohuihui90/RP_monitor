#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from s3lib.p0.jsonio import write_json
from s3lib.p0.timeutil import utc_now


FORBIDDEN_CLAIMS = [
    "object_root_caused_vrp_root",
    "validator_cache_root_equals_accepted_object_set",
    "validator_logical_cache_index_root_equals_accepted_object_set",
    "validator_cache_view_caused_vrp_output",
    "validator_implementation_divergence",
    "high_confidence_attribution",
    "high_confidence_e4_attribution",
    "observer_object_view_equals_validator_input",
]

SAFE_KEYS = {
    "disallowed_claims",
    "forbidden_claims",
    "semantic_note",
}

SCAN_SUFFIXES = {
    ".json",
    ".jsonl",
    ".md",
    ".txt",
}


def json_load(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None


def should_skip_file(path: Path) -> bool:
    name = path.name

    # Do not scan semantic guardrail's own previous output, otherwise old
    # violation records recursively become new violations.
    if name in {
        "M16_SEMANTIC_GUARDRAIL.json",
        "M16_SEMANTIC_GUARDRAIL.txt",
    }:
        return True

    # Raw VRP files are large data, not claims.
    if "/outputs/raw_vrp/" in str(path):
        return True

    return False


def iter_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []

    for root in paths:
        if not root.exists():
            continue

        if root.is_file():
            if root.suffix in SCAN_SUFFIXES and not should_skip_file(root):
                files.append(root)
            continue

        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if should_skip_file(p):
                continue
            if p.suffix in SCAN_SUFFIXES:
                files.append(p)

    return sorted(set(files))


def is_safe_json_path(path_stack: list[str]) -> bool:
    """
    Claims listed under disallowed/forbidden fields are safety guardrails,
    not actual strong attribution claims. Skip the whole subtree.
    """
    for key in path_stack:
        low = str(key).lower()
        if (
            "disallowed" in low
            or "forbidden" in low
            or "semantic_note" in low
            or "allowed_claims" in low
        ):
            return True
    return False


def scan_json_value(value: Any, path_stack: list[str], file_path: Path) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []

    if is_safe_json_path(path_stack):
        return violations

    if isinstance(value, dict):
        for k, v in value.items():
            violations.extend(scan_json_value(v, path_stack + [str(k)], file_path))
        return violations

    if isinstance(value, list):
        for i, item in enumerate(value):
            violations.extend(scan_json_value(item, path_stack + [str(i)], file_path))
        return violations

    if isinstance(value, str):
        low = value.lower()

        # Lines that explicitly negate or prohibit a claim are not violations.
        if (
            "disallowed" in low
            or "forbidden" in low
            or "does not claim" in low
            or "not claim" in low
            or "不得输出" in low
            or "禁止" in low
        ):
            return violations

        for claim in FORBIDDEN_CLAIMS:
            if claim in value:
                violations.append({
                    "file": str(file_path),
                    "json_path": ".".join(path_stack),
                    "claim": claim,
                    "context": value[:500],
                })

    return violations


def scan_json_file(path: Path) -> list[dict[str, Any]]:
    obj = json_load(path)
    if obj is None:
        return scan_text_file(path)

    return scan_json_value(obj, [], path)


def scan_jsonl_file(path: Path) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []

    for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue

        try:
            obj = json.loads(line)
        except Exception:
            for claim in FORBIDDEN_CLAIMS:
                if claim in line:
                    violations.append({
                        "file": str(path),
                        "line": line_no,
                        "claim": claim,
                        "context": line[:500],
                    })
            continue

        line_violations = scan_json_value(obj, [f"line_{line_no}"], path)
        violations.extend(line_violations)

    return violations


def scan_text_file(path: Path) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []

    text = path.read_text(encoding="utf-8", errors="ignore")

    # Markdown / txt evidence packs may intentionally list forbidden phrases
    # inside a "Disallowed claims" or "Forbidden claims" section.
    # We skip that entire section until the next Markdown heading.
    in_safe_section = False

    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        low = stripped.lower()

        # Section boundary handling for markdown.
        if stripped.startswith("#"):
            if (
                "disallowed claims" in low
                or "forbidden claims" in low
                or "semantic note" in low
            ):
                in_safe_section = True
            else:
                in_safe_section = False

        if in_safe_section:
            continue

        # Also allow single lines that explicitly describe prohibition.
        if (
            "disallowed" in low
            or "forbidden" in low
            or "not claim" in low
            or "does not claim" in low
            or "不得输出" in low
            or "禁止" in low
        ):
            continue

        for claim in FORBIDDEN_CLAIMS:
            if claim in line:
                violations.append({
                    "file": str(path),
                    "line": line_no,
                    "claim": claim,
                    "context": line[:500],
                })

    return violations


def scan_file(path: Path) -> list[dict[str, Any]]:
    if path.suffix == ".json":
        return scan_json_file(path)
    if path.suffix == ".jsonl":
        return scan_jsonl_file(path)
    return scan_text_file(path)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--history-root", default="data/p3_collector/m245_three_layer_baseline/history")
    ap.add_argument("--report-dir", default="data/p3_collector/m245_three_layer_baseline/reports")
    ap.add_argument("--evidence-pack-root", default="data/p3_collector/m245_three_layer_baseline/evidence_packs")
    args = ap.parse_args()

    roots = [
        Path(args.history_root),
        Path(args.report_dir),
        Path(args.evidence_pack_root),
    ]

    files = iter_files(roots)

    violations: list[dict[str, Any]] = []

    for f in files:
        # Avoid scanning raw VRP files. They are large raw data and not claims.
        path_text = str(f)
        if "/outputs/raw_vrp/" in path_text:
            continue

        violations.extend(scan_file(f))

    status = "PASS" if not violations else "FAIL"

    summary = {
        "schema": "s3.p0.semantic_guardrail_result.v1",
        "generated_at_utc": utc_now(),
        "guardrail_status": status,
        "no_forbidden_strong_claim": not violations,
        "forbidden_claims": FORBIDDEN_CLAIMS,
        "checked_files": len(files),
        "violation_count": len(violations),
        "violations": violations,
    }

    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    write_json(report_dir / "M16_SEMANTIC_GUARDRAIL.json", summary)

    txt = [
        f"M16_SEMANTIC_GUARDRAIL={status}",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"checked_files = {summary['checked_files']}",
        f"violation_count = {summary['violation_count']}",
        f"no_forbidden_strong_claim = {summary['no_forbidden_strong_claim']}",
    ]

    if violations:
        txt.append("")
        txt.append("violations:")
        for v in violations[:50]:
            txt.append(f"- {v}")

    (report_dir / "M16_SEMANTIC_GUARDRAIL.txt").write_text("\n".join(txt) + "\n", encoding="utf-8")

    print("\n".join(txt))


if __name__ == "__main__":
    main()
