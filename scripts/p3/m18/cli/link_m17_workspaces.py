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


OBJECT_SUFFIX_RE = re.compile(
    r"(cache://[^\s\"'<>]+|rsync://[^\s\"'<>]+|https?://[^\s\"'<>]+)"
    r"\.(mft|roa|cer|crl|gbr|aspa|asa|sig|tak)",
    re.IGNORECASE,
)

MAX_SCAN_BYTES = 20 * 1024 * 1024


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
    path.write_text(
        json.dumps(obj, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            count += 1

    return count


def normalize_uri(uri: str | None) -> str | None:
    if not uri:
        return None

    s = str(uri).strip().strip(",;)]}")
    if not s:
        return None

    if s.startswith("rsync://"):
        return "cache://.rpki-cache/repository/rsync/" + s[len("rsync://"):]

    return s


def load_identity_index(identity_index: Path) -> Dict[str, Dict[str, Any]]:
    by_uri = {}

    for row in read_jsonl(identity_index):
        uri = normalize_uri(row.get("canonical_uri") or row.get("object_uri"))
        if not uri:
            continue
        by_uri[uri] = row

    return by_uri


def extract_uris_from_text(text: str) -> list[str]:
    uris = []

    for match in OBJECT_SUFFIX_RE.finditer(text):
        raw = match.group(0)
        uri = normalize_uri(raw)
        if uri:
            uris.append(uri)

    return sorted(set(uris))


def scan_workspace_uris(workspace: Path) -> Dict[str, Any]:
    uri_hits = Counter()
    scanned_files = 0
    skipped_large_files = 0

    for path in workspace.rglob("*"):
        if not path.is_file():
            continue

        if path.stat().st_size > MAX_SCAN_BYTES:
            skipped_large_files += 1
            continue

        if path.suffix.lower() not in {".json", ".jsonl", ".txt", ".md", ".csv"}:
            continue

        scanned_files += 1

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        for uri in extract_uris_from_text(text):
            uri_hits[uri] += 1

    return {
        "workspace": str(workspace),
        "scanned_files": scanned_files,
        "skipped_large_files": skipped_large_files,
        "uri_hits": dict(uri_hits),
    }


def link_one_workspace(
    workspace: Path,
    identity_by_uri: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    scan = scan_workspace_uris(workspace)

    linked = []
    unmatched = []

    for uri, hit_count in sorted(scan["uri_hits"].items()):
        identity = identity_by_uri.get(uri)

        if identity:
            linked.append({
                "uri": uri,
                "hit_count": hit_count,
                "hash_level_status": identity.get("hash_level_status"),
                "probe_count": identity.get("probe_count"),
                "recovered_probe_count": identity.get("recovered_probe_count"),
                "distinct_raw_sha256_count": identity.get("distinct_raw_sha256_count"),
                "object_type": identity.get("object_type"),
                "object_family": identity.get("object_family"),
                "probe_values": identity.get("probe_values"),
            })
        else:
            unmatched.append({
                "uri": uri,
                "hit_count": hit_count,
            })

    return {
        "schema": "s3.m18e.m17_workspace_linkage.v1",
        "created_at_utc": utc_now_iso(),
        "workspace": str(workspace),
        "workspace_name": workspace.name,
        "scanned_files": scan["scanned_files"],
        "skipped_large_files": scan["skipped_large_files"],
        "uri_count": len(scan["uri_hits"]),
        "linked_uri_count": len(linked),
        "unmatched_uri_count": len(unmatched),
        "linked_identities": linked,
        "unmatched_uris": unmatched[:200],
    }


def discover_m17_object_workspaces(m17_root: Path) -> list[Path]:
    return sorted(
        p for p in m17_root.glob("anom_*object_view*")
        if p.is_dir()
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="M18-E Link M17 workspaces with M18 identity index")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--m17-root", required=True)
    parser.add_argument("--identity-index", required=True)
    parser.add_argument("--max-workspaces", type=int, default=0)
    args = parser.parse_args()

    run_dir = Path(args.run_dir).expanduser().resolve()
    m17_root = Path(args.m17_root).expanduser().resolve()
    identity_index = Path(args.identity_index).expanduser().resolve()

    linkage_dir = run_dir / "linkage"
    outputs_dir = run_dir / "outputs"
    checks_dir = run_dir / "checks"

    linkage_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)
    checks_dir.mkdir(parents=True, exist_ok=True)

    identity_by_uri = load_identity_index(identity_index)
    workspaces = discover_m17_object_workspaces(m17_root)

    if args.max_workspaces and args.max_workspaces > 0:
        workspaces = workspaces[:args.max_workspaces]

    linkage_rows = []

    for workspace in workspaces:
        row = link_one_workspace(
            workspace=workspace,
            identity_by_uri=identity_by_uri,
        )
        linkage_rows.append(row)

    linked_workspace_count = sum(
        1 for row in linkage_rows
        if row.get("linked_uri_count", 0) > 0
    )

    total_uri_count = sum(row.get("uri_count", 0) for row in linkage_rows)
    total_linked_uri_count = sum(row.get("linked_uri_count", 0) for row in linkage_rows)
    total_unmatched_uri_count = sum(row.get("unmatched_uri_count", 0) for row in linkage_rows)

    by_workspace_link_status = Counter(
        "linked" if row.get("linked_uri_count", 0) > 0 else "no_link"
        for row in linkage_rows
    )

    linkage_path = linkage_dir / "m17_workspace_m18_linkage.jsonl"
    summary_path = outputs_dir / "M18E_m17_workspace_linkage_summary.json"
    check_path = checks_dir / "M18E_m17_workspace_linkage.txt"

    write_jsonl(linkage_path, linkage_rows)

    warnings = []
    if total_linked_uri_count == 0:
        warnings.append("no_m18_identity_link_found_current_recoverable_subset")

    status = "PASS" if len(workspaces) > 0 and linkage_path.exists() else "FAIL"

    summary = {
        "schema": "s3.m18e.m17_workspace_linkage_summary.v1",
        "status": status,
        "created_at_utc": utc_now_iso(),
        "scope": "m17_object_view_to_m18_recoverable_identity_linkage",
        "run_dir": str(run_dir),
        "m17_root": str(m17_root),
        "identity_index": str(identity_index),
        "identity_count": len(identity_by_uri),
        "workspace_count": len(workspaces),
        "linked_workspace_count": linked_workspace_count,
        "total_uri_count": total_uri_count,
        "total_linked_uri_count": total_linked_uri_count,
        "total_unmatched_uri_count": total_unmatched_uri_count,
        "by_workspace_link_status": dict(by_workspace_link_status),
        "linkage_path": str(linkage_path),
        "summary_path": str(summary_path),
        "warnings": warnings,
    }

    write_json(summary_path, summary)

    text = "\n".join([
        f"M18E_M17_WORKSPACE_LINKAGE={status}",
        "",
        "scope = m17_object_view_to_m18_recoverable_identity_linkage",
        f"identity_count = {summary['identity_count']}",
        f"workspace_count = {summary['workspace_count']}",
        f"linked_workspace_count = {summary['linked_workspace_count']}",
        f"total_uri_count = {summary['total_uri_count']}",
        f"total_linked_uri_count = {summary['total_linked_uri_count']}",
        f"total_unmatched_uri_count = {summary['total_unmatched_uri_count']}",
        f"by_workspace_link_status = {summary['by_workspace_link_status']}",
        f"warnings = {warnings}",
        "",
        f"linkage_path = {linkage_path}",
        f"summary_path = {summary_path}",
    ]) + "\n"

    check_path.write_text(text, encoding="utf-8")
    print(text)

    return 0 if status == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
