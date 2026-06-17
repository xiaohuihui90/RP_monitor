#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable


OBJECT_URI_RE = re.compile(
    r"(cache://[^\s\"'<>]+|rsync://[^\s\"'<>]+|https?://[^\s\"'<>]+)"
    r"\.(mft|roa|cer|crl|gbr|aspa|asa|sig|tak)",
    re.IGNORECASE,
)

MAX_SCAN_BYTES = 20 * 1024 * 1024


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


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


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)

    n = 0
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            n += 1

    return n


def normalize_uri(uri: str | None) -> str | None:
    if not uri:
        return None

    s = str(uri).strip().strip(",;)]}\"'")
    if not s:
        return None

    if s.startswith("rsync://"):
        return "cache://.rpki-cache/repository/rsync/" + s[len("rsync://"):]

    return s


def discover_m17_object_workspaces(m17_root: Path) -> list[Path]:
    return sorted(
        p for p in m17_root.glob("anom_*object_view*")
        if p.is_dir()
    )


def extract_workspace_uris(workspace: Path) -> Dict[str, Any]:
    uri_hits = Counter()
    scanned_files = 0
    skipped_large_files = 0

    for path in workspace.rglob("*"):
        if not path.is_file():
            continue

        try:
            size = path.stat().st_size
        except Exception:
            continue

        if size > MAX_SCAN_BYTES:
            skipped_large_files += 1
            continue

        if path.suffix.lower() not in {".json", ".jsonl", ".txt", ".md", ".csv"}:
            continue

        scanned_files += 1

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        for m in OBJECT_URI_RE.finditer(text):
            uri = normalize_uri(m.group(0))
            if uri:
                uri_hits[uri] += 1

    return {
        "scanned_files": scanned_files,
        "skipped_large_files": skipped_large_files,
        "uri_hits": dict(uri_hits),
    }


def load_object_diff_by_uri(object_diff_index: Path) -> Dict[str, Dict[str, Any]]:
    out = {}

    for row in read_jsonl(object_diff_index):
        uri = normalize_uri(row.get("canonical_uri") or row.get("object_uri"))
        if uri:
            out[uri] = row

    return out


def load_semantic_by_object_diff_id(semantic_diffs_dir: Path) -> Dict[str, Dict[str, Any]]:
    out = {}

    for path in semantic_diffs_dir.rglob("semantic_diff.json"):
        try:
            obj = read_json(path)
        except Exception:
            continue

        object_diff_id = obj.get("object_diff_id")
        if object_diff_id:
            out[object_diff_id] = obj

    return out


def make_ref(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "object_diff_id": row.get("object_diff_id"),
        "identity_key": row.get("identity_key"),
        "canonical_uri": row.get("canonical_uri"),
        "object_type": row.get("object_type"),
        "raw_hash_status": row.get("raw_hash_status"),
        "diff_candidate_type": row.get("diff_candidate_type"),
        "semantic_diff_required": row.get("semantic_diff_required"),
        "semantic_diff_status": row.get("semantic_diff_status"),
        "severity": row.get("severity"),
        "coverage_scope": row.get("coverage_scope"),
    }


def writeback_one_workspace(
    workspace: Path,
    object_diff_by_uri: Dict[str, Dict[str, Any]],
    semantic_by_id: Dict[str, Dict[str, Any]],
    m19_run_dir: Path,
) -> Dict[str, Any]:
    scan = extract_workspace_uris(workspace)

    evidence_dir = workspace / "m19_object_diff_evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    object_refs = []
    semantic_refs = []
    unmatched_uris = []

    for uri, hit_count in sorted(scan["uri_hits"].items()):
        row = object_diff_by_uri.get(uri)

        if not row:
            unmatched_uris.append({"uri": uri, "hit_count": hit_count})
            continue

        ref = make_ref(row)
        ref["hit_count"] = hit_count
        ref["match_type"] = "direct_uri"
        object_refs.append(ref)

        semantic = semantic_by_id.get(row.get("object_diff_id"))
        if semantic:
            semantic_refs.append({
                "object_diff_id": row.get("object_diff_id"),
                "canonical_uri": row.get("canonical_uri"),
                "semantic_diff_status": semantic.get("semantic_diff_status"),
                "semantic_class": (semantic.get("interpretation") or {}).get("semantic_class"),
                "semantic_diff_path": str(
                    m19_run_dir / "semantic_diffs" / str(row.get("object_diff_id")) / "semantic_diff.json"
                ),
                "match_type": "direct_uri",
            })

    if object_refs:
        writeback_status = "written"
    elif scan["uri_hits"]:
        writeback_status = "no_candidate"
    else:
        writeback_status = "no_direct_link"

    write_jsonl(evidence_dir / "object_diff_index_refs.jsonl", object_refs)
    write_jsonl(evidence_dir / "semantic_diff_refs.jsonl", semantic_refs)

    summary = {
        "schema": "s3.m19.workspace_diff_summary.v1",
        "created_at_utc": utc_now_iso(),
        "workspace": str(workspace),
        "workspace_name": workspace.name,
        "m19_run_dir": str(m19_run_dir),
        "evidence_dir": str(evidence_dir),
        "writeback_status": writeback_status,
        "coverage_scope": "recoverable_subset",
        "full_raw_byte_coverage": False,
        "scanned_files": scan["scanned_files"],
        "skipped_large_files": scan["skipped_large_files"],
        "uri_count": len(scan["uri_hits"]),
        "object_diff_ref_count": len(object_refs),
        "semantic_diff_ref_count": len(semantic_refs),
        "unmatched_uri_count": len(unmatched_uris),
        "unmatched_uris": unmatched_uris[:200],
        "important_boundary": [
            "M19 writeback uses recoverable-subset object_diff_index.",
            "No direct link means the workspace did not expose URI-level references matchable to current M19 input.",
            "This does not imply absence of object-layer anomaly.",
        ],
    }

    write_json(evidence_dir / "M19_workspace_diff_summary.json", summary)

    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="M19-E write back M19 evidence to M17 workspaces")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--m17-root", required=True)
    parser.add_argument("--object-diff-index", required=True)
    parser.add_argument("--semantic-diffs-dir", required=True)
    parser.add_argument("--max-workspaces", type=int, default=0)
    args = parser.parse_args()

    run_dir = Path(args.run_dir).expanduser().resolve()
    m17_root = Path(args.m17_root).expanduser().resolve()
    object_diff_index = Path(args.object_diff_index).expanduser().resolve()
    semantic_diffs_dir = Path(args.semantic_diffs_dir).expanduser().resolve()

    outputs_dir = run_dir / "outputs"
    checks_dir = run_dir / "checks"
    workspace_updates_dir = run_dir / "workspace_updates"

    outputs_dir.mkdir(parents=True, exist_ok=True)
    checks_dir.mkdir(parents=True, exist_ok=True)
    workspace_updates_dir.mkdir(parents=True, exist_ok=True)

    object_diff_by_uri = load_object_diff_by_uri(object_diff_index)
    semantic_by_id = load_semantic_by_object_diff_id(semantic_diffs_dir)

    workspaces = discover_m17_object_workspaces(m17_root)

    if args.max_workspaces and args.max_workspaces > 0:
        workspaces = workspaces[:args.max_workspaces]

    workspace_summaries = []

    for workspace in workspaces:
        summary = writeback_one_workspace(
            workspace=workspace,
            object_diff_by_uri=object_diff_by_uri,
            semantic_by_id=semantic_by_id,
            m19_run_dir=run_dir,
        )
        workspace_summaries.append(summary)

    by_status = Counter(s.get("writeback_status") for s in workspace_summaries)

    direct_linked_workspace_count = sum(
        1 for s in workspace_summaries
        if s.get("object_diff_ref_count", 0) > 0
    )

    total_object_refs = sum(s.get("object_diff_ref_count", 0) for s in workspace_summaries)
    total_semantic_refs = sum(s.get("semantic_diff_ref_count", 0) for s in workspace_summaries)
    total_uri_count = sum(s.get("uri_count", 0) for s in workspace_summaries)

    write_jsonl(
        workspace_updates_dir / "M19_workspace_writeback_summaries.jsonl",
        workspace_summaries,
    )

    if direct_linked_workspace_count > 0:
        status = "PASS"
    else:
        status = "PASS_WITH_NO_DIRECT_LINK"

    summary_path = outputs_dir / "M19E_workspace_writeback_summary.json"
    check_path = checks_dir / "M19E_workspace_writeback.txt"

    summary = {
        "schema": "s3.m19e.workspace_writeback_summary.v1",
        "status": status,
        "created_at_utc": utc_now_iso(),
        "run_dir": str(run_dir),
        "m17_root": str(m17_root),
        "object_diff_index": str(object_diff_index),
        "semantic_diffs_dir": str(semantic_diffs_dir),
        "object_diff_index_count": len(object_diff_by_uri),
        "semantic_evidence_count": len(semantic_by_id),
        "workspace_count": len(workspaces),
        "direct_linked_workspace_count": direct_linked_workspace_count,
        "total_uri_count": total_uri_count,
        "total_object_diff_ref_count": total_object_refs,
        "total_semantic_diff_ref_count": total_semantic_refs,
        "by_workspace_writeback_status": dict(by_status),
        "workspace_updates_index": str(workspace_updates_dir / "M19_workspace_writeback_summaries.jsonl"),
        "warnings": (
            ["no_direct_uri_link_found_for_current_recoverable_subset"]
            if direct_linked_workspace_count == 0 else []
        ),
        "important_boundary": [
            "M19-E writes evidence summaries into M17 object_view workspaces.",
            "PASS_WITH_NO_DIRECT_LINK is acceptable when M17 workspaces do not expose directly matchable object URIs.",
            "Current M19 input is recoverable subset, not full raw-byte coverage.",
        ],
    }

    write_json(summary_path, summary)

    text = "\n".join([
        f"M19E_WORKSPACE_WRITEBACK={status}",
        "",
        "scope = writeback_m19_evidence_to_m17_object_view_workspaces",
        f"object_diff_index_count = {summary['object_diff_index_count']}",
        f"semantic_evidence_count = {summary['semantic_evidence_count']}",
        f"workspace_count = {summary['workspace_count']}",
        f"direct_linked_workspace_count = {summary['direct_linked_workspace_count']}",
        f"total_uri_count = {summary['total_uri_count']}",
        f"total_object_diff_ref_count = {summary['total_object_diff_ref_count']}",
        f"total_semantic_diff_ref_count = {summary['total_semantic_diff_ref_count']}",
        f"by_workspace_writeback_status = {summary['by_workspace_writeback_status']}",
        f"warnings = {summary['warnings']}",
        "",
        f"workspace_updates_index = {summary['workspace_updates_index']}",
        f"summary_path = {summary_path}",
        "",
        "important_boundary = PASS_WITH_NO_DIRECT_LINK is acceptable for current recoverable subset.",
    ]) + "\n"

    check_path.write_text(text, encoding="utf-8")
    print(text)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
