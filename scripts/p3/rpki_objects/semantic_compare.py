#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MFT semantic inventory pairwise compare.

Batch 5 scope:
  - Compare MFT-only semantic_object_inventory.jsonl across probes
  - Classify differences by canonical_uri and semantic manifest fields
  - Keep legacy wrapper hash only as diagnostic evidence
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from scripts.p3.rpki_objects.semantic_hash import canonical_json_hash


def read_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with Path(path).open("r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                obj["_line_no"] = line_no
                yield obj
            except Exception as exc:
                yield {
                    "_line_no": line_no,
                    "_json_parse_error": repr(exc),
                    "_raw": line[:500],
                }


def compact_record(r: Dict[str, Any]) -> Dict[str, Any]:
    sf = r.get("semantic_fields") or {}
    return {
        "probe_id": r.get("probe_id"),
        "canonical_uri": r.get("canonical_uri"),
        "repo_host": r.get("repo_host"),
        "object_type": r.get("object_type"),
        "parse_status": r.get("parse_status"),
        "warnings": r.get("warnings") or [],

        "semantic_object_hash": r.get("semantic_object_hash"),
        "wrapper_sha256": r.get("wrapper_sha256"),
        "wrapper_detected": r.get("wrapper_detected"),
        "wrapper_type": r.get("wrapper_type"),
        "cms_payload_sha256": r.get("cms_payload_sha256"),
        "econtent_sha256": r.get("econtent_sha256"),

        "manifest_number": sf.get("manifest_number"),
        "this_update": sf.get("this_update"),
        "next_update": sf.get("next_update"),
        "file_hash_alg": sf.get("file_hash_alg"),
        "file_count": sf.get("file_count"),
        "file_list_digest": sf.get("file_list_digest"),

        "source_file": r.get("source_file"),
        "source_file_sha256": r.get("source_file_sha256"),
        "_line_no": r.get("_line_no"),
    }


def load_inventory(path: Path) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Any]]:
    """
    Load semantic inventory into canonical_uri -> compact record.

    If duplicate canonical_uri appears inside one probe, keep the first record
    and count whether duplicates are same semantic hash or conflicting.
    """
    index: Dict[str, Dict[str, Any]] = {}
    counters = Counter()
    parse_status_counts = Counter()
    repo_counts = Counter()
    duplicate_conflicts: List[Dict[str, Any]] = []

    for r in read_jsonl(path):
        counters["input_rows"] += 1

        if "_json_parse_error" in r:
            counters["json_parse_failed"] += 1
            continue

        cr = compact_record(r)
        uri = cr.get("canonical_uri")
        if not uri:
            counters["missing_canonical_uri"] += 1
            continue

        parse_status_counts[str(cr.get("parse_status"))] += 1
        repo_counts[str(cr.get("repo_host") or "unknown")] += 1

        if uri in index:
            counters["duplicate_uri"] += 1
            old = index[uri]
            if old.get("semantic_object_hash") == cr.get("semantic_object_hash"):
                counters["duplicate_same_semantic_hash"] += 1
            else:
                counters["duplicate_conflicting_semantic_hash"] += 1
                if len(duplicate_conflicts) < 100:
                    duplicate_conflicts.append({
                        "canonical_uri": uri,
                        "old_semantic_object_hash": old.get("semantic_object_hash"),
                        "new_semantic_object_hash": cr.get("semantic_object_hash"),
                        "old_parse_status": old.get("parse_status"),
                        "new_parse_status": cr.get("parse_status"),
                    })
            continue

        index[uri] = cr

    semantic_triples = sorted(
        f"{uri}|mft|{rec.get('semantic_object_hash')}"
        for uri, rec in index.items()
        if rec.get("parse_status") == "ok" and rec.get("semantic_object_hash")
    )

    summary = {
        "path": str(path),
        "unique_uri_count": len(index),
        "semantic_ok_uri_count": sum(
            1 for r in index.values()
            if r.get("parse_status") == "ok" and r.get("semantic_object_hash")
        ),
        "semantic_object_root_recomputed": canonical_json_hash(semantic_triples),
        "counters": dict(counters),
        "parse_status_counts": dict(parse_status_counts),
        "repo_counts": dict(repo_counts),
        "duplicate_conflict_samples": duplicate_conflicts,
    }
    return index, summary


def _int_or_none(v: Any):
    try:
        if v is None:
            return None
        return int(v)
    except Exception:
        return None


def classify_pair(left: Dict[str, Any] | None, right: Dict[str, Any] | None) -> str:
    if left is None and right is not None:
        return "right_only_uri"
    if right is None and left is not None:
        return "left_only_uri"
    if left is None and right is None:
        return "missing_both_impossible"

    lp = left.get("parse_status")
    rp = right.get("parse_status")

    if lp != "ok" or rp != "ok":
        if lp == rp:
            return "both_unparsed_same_status"
        return "unparsed_or_missing"

    lh = left.get("semantic_object_hash")
    rh = right.get("semantic_object_hash")

    if lh and rh and lh == rh:
        lw = left.get("wrapper_sha256")
        rw = right.get("wrapper_sha256")
        if lw and rw and lw != rw:
            return "same_semantic_hash_diff_wrapper"
        return "same_semantic_hash"

    le = left.get("econtent_sha256")
    re = right.get("econtent_sha256")
    if le and re and le == re:
        return "same_econtent_hash_diff_semantic_hash"

    lc = left.get("cms_payload_sha256")
    rc = right.get("cms_payload_sha256")
    if lc and rc and lc == rc:
        return "same_cms_payload_hash_diff_semantic_hash"

    lm = _int_or_none(left.get("manifest_number"))
    rm = _int_or_none(right.get("manifest_number"))

    if lm is not None and rm is not None:
        if lm == rm:
            if left.get("file_list_digest") != right.get("file_list_digest"):
                return "same_manifest_number_filelist_diff"
            return "same_manifest_number_metadata_diff"
        if abs(lm - rm) == 1:
            return "adjacent_manifest_number_skew"
        return "manifest_number_skew"

    if left.get("file_list_digest") and right.get("file_list_digest"):
        if left.get("file_list_digest") != right.get("file_list_digest"):
            return "file_list_diff_no_manifest_number"

    return "diff_semantic_hash_unknown"


def pair_diff_sample(
    uri: str,
    left_probe: str,
    right_probe: str,
    left: Dict[str, Any] | None,
    right: Dict[str, Any] | None,
    classification: str,
) -> Dict[str, Any]:
    def shrink(x):
        if x is None:
            return None
        return {
            "parse_status": x.get("parse_status"),
            "semantic_object_hash": x.get("semantic_object_hash"),
            "wrapper_sha256": x.get("wrapper_sha256"),
            "cms_payload_sha256": x.get("cms_payload_sha256"),
            "econtent_sha256": x.get("econtent_sha256"),
            "manifest_number": x.get("manifest_number"),
            "this_update": x.get("this_update"),
            "next_update": x.get("next_update"),
            "file_count": x.get("file_count"),
            "file_list_digest": x.get("file_list_digest"),
            "source_file": x.get("source_file"),
            "warnings": x.get("warnings"),
        }

    repo_host = (
        (left or {}).get("repo_host")
        or (right or {}).get("repo_host")
        or "unknown"
    )

    return {
        "canonical_uri": uri,
        "repo_host": repo_host,
        "left_probe": left_probe,
        "right_probe": right_probe,
        "classification": classification,
        "left": shrink(left),
        "right": shrink(right),
    }


def compare_pair(
    left_probe: str,
    right_probe: str,
    left_index: Dict[str, Dict[str, Any]],
    right_index: Dict[str, Dict[str, Any]],
    *,
    sample_limit_per_class: int = 50,
) -> Dict[str, Any]:
    all_uris = sorted(set(left_index.keys()) | set(right_index.keys()))
    shared_uris = sorted(set(left_index.keys()) & set(right_index.keys()))

    class_counts = Counter()
    repo_class_counts = defaultdict(Counter)
    samples = defaultdict(list)

    for uri in all_uris:
        left = left_index.get(uri)
        right = right_index.get(uri)
        cls = classify_pair(left, right)
        class_counts[cls] += 1

        repo_host = (
            (left or {}).get("repo_host")
            or (right or {}).get("repo_host")
            or "unknown"
        )
        repo_class_counts[repo_host][cls] += 1

        # Do not store too many same entries.
        if cls not in {"same_semantic_hash", "same_semantic_hash_diff_wrapper"}:
            if len(samples[cls]) < sample_limit_per_class:
                samples[cls].append(
                    pair_diff_sample(uri, left_probe, right_probe, left, right, cls)
                )
        elif cls == "same_semantic_hash_diff_wrapper":
            if len(samples[cls]) < sample_limit_per_class:
                samples[cls].append(
                    pair_diff_sample(uri, left_probe, right_probe, left, right, cls)
                )

    semantic_aligned_count = (
        class_counts.get("same_semantic_hash", 0)
        + class_counts.get("same_semantic_hash_diff_wrapper", 0)
    )

    semantic_diff_classes = {
        k: v for k, v in class_counts.items()
        if k not in {"same_semantic_hash", "same_semantic_hash_diff_wrapper"}
    }

    return {
        "left_probe": left_probe,
        "right_probe": right_probe,
        "left_uri_count": len(left_index),
        "right_uri_count": len(right_index),
        "shared_uri_count": len(shared_uris),
        "union_uri_count": len(all_uris),
        "uri_jaccard": (len(shared_uris) / len(all_uris)) if all_uris else None,
        "semantic_aligned_count": semantic_aligned_count,
        "semantic_aligned_ratio_on_union": (
            semantic_aligned_count / len(all_uris)
        ) if all_uris else None,
        "classification_counts": dict(class_counts),
        "semantic_diff_classes": semantic_diff_classes,
        "repo_class_counts": {
            repo: dict(counter)
            for repo, counter in sorted(repo_class_counts.items())
        },
        "samples": dict(samples),
    }


def infer_overall_status(pair_reports: Dict[str, Any]) -> Dict[str, Any]:
    total = Counter()
    for pair, report in pair_reports.items():
        total.update(report.get("classification_counts", {}))

    true_diff = sum(
        v for k, v in total.items()
        if k not in {
            "same_semantic_hash",
            "same_semantic_hash_diff_wrapper",
        }
    )

    adjacent = total.get("adjacent_manifest_number_skew", 0)
    wrapper_only = total.get("same_semantic_hash_diff_wrapper", 0)
    filelist_same_mn = total.get("same_manifest_number_filelist_diff", 0)
    unknown = total.get("diff_semantic_hash_unknown", 0)

    if true_diff == 0:
        status = "mft_semantic_views_aligned_or_wrapper_only"
        recommendation = "do_not_attribute_to_real_mft_payload_divergence"
    elif adjacent >= max(1, int(true_diff * 0.5)):
        status = "mft_semantic_divergence_manifest_version_skew_dominant"
        recommendation = "treat_as_temporal_version_skew_candidate_then_join_window_context"
    elif filelist_same_mn > 0:
        status = "mft_semantic_divergence_same_manifest_number_filelist_diff_observed"
        recommendation = "high_priority_investigation_and_possible_object_to_vrp_mapping"
    elif unknown > 0:
        status = "mft_semantic_divergence_needs_manual_drilldown"
        recommendation = "inspect_unknown_diff_samples_before_e4_mapping"
    else:
        status = "mft_semantic_divergence_observed"
        recommendation = "continue_to_filelist_and_roa_impact_mapping_if_roa_related"

    return {
        "overall_status": status,
        "recommendation": recommendation,
        "aggregate_classification_counts": dict(total),
        "true_diff_count_excluding_wrapper_only": true_diff,
        "wrapper_only_count": wrapper_only,
        "adjacent_manifest_number_skew_count": adjacent,
        "same_manifest_number_filelist_diff_count": filelist_same_mn,
        "unknown_diff_count": unknown,
    }


def compare_semantic_inventories(
    probe_inventory_paths: Dict[str, Path],
    out_dir: Path,
    *,
    sample_limit_per_class: int = 50,
) -> Dict[str, Any]:
    out_dir = Path(out_dir)
    (out_dir / "checks").mkdir(parents=True, exist_ok=True)
    (out_dir / "outputs").mkdir(parents=True, exist_ok=True)
    (out_dir / "diffs").mkdir(parents=True, exist_ok=True)

    indexes = {}
    inventory_summaries = {}

    for probe, path in probe_inventory_paths.items():
        idx, summary = load_inventory(Path(path))
        indexes[probe] = idx
        inventory_summaries[probe] = summary

    probes = list(probe_inventory_paths.keys())
    pair_reports = {}

    for i in range(len(probes)):
        for j in range(i + 1, len(probes)):
            left_probe = probes[i]
            right_probe = probes[j]
            pair_key = f"{left_probe}_vs_{right_probe}"

            report = compare_pair(
                left_probe,
                right_probe,
                indexes[left_probe],
                indexes[right_probe],
                sample_limit_per_class=sample_limit_per_class,
            )
            pair_reports[pair_key] = report

            (out_dir / "diffs" / f"{pair_key}_mft_semantic_pair_report.json").write_text(
                json.dumps(report, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

    overall = infer_overall_status(pair_reports)

    root_groups = defaultdict(list)
    roots = {
        probe: inventory_summaries[probe]["semantic_object_root_recomputed"]
        for probe in probes
    }
    for probe, root in roots.items():
        root_groups[root].append(probe)

    summary = {
        "schema": "s3.stage3.semantic_object_layer.batch5_mft_semantic_compare.v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "MFT-only semantic compare across probe semantic inventories",
        "probes": probes,
        "semantic_object_roots_recomputed": roots,
        "semantic_object_root_groups_recomputed": dict(root_groups),
        "semantic_object_roots_aligned_recomputed": len(root_groups) == 1,
        "inventory_summaries": inventory_summaries,
        "pair_reports": {
            k: {
                kk: vv for kk, vv in v.items()
                if kk != "samples"
            }
            for k, v in pair_reports.items()
        },
        "overall": overall,
        "pair_report_files": {
            k: str(out_dir / "diffs" / f"{k}_mft_semantic_pair_report.json")
            for k in pair_reports
        },
        "next_stage": "Batch5-R or Batch6_ROA_parser depending on overall status",
    }

    summary_path = out_dir / "outputs" / "M16_Batch5_mft_semantic_compare_summary.json"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    lines = [
        "M16_BATCH5_MFT_SEMANTIC_COMPARE=DONE",
        "",
        f"created_at_utc = {summary['created_at_utc']}",
        f"semantic_object_roots_aligned_recomputed = {summary['semantic_object_roots_aligned_recomputed']}",
        f"overall_status = {overall['overall_status']}",
        f"recommendation = {overall['recommendation']}",
        "",
        f"aggregate_classification_counts = {overall['aggregate_classification_counts']}",
        f"true_diff_count_excluding_wrapper_only = {overall['true_diff_count_excluding_wrapper_only']}",
        f"wrapper_only_count = {overall['wrapper_only_count']}",
        f"adjacent_manifest_number_skew_count = {overall['adjacent_manifest_number_skew_count']}",
        f"same_manifest_number_filelist_diff_count = {overall['same_manifest_number_filelist_diff_count']}",
        f"unknown_diff_count = {overall['unknown_diff_count']}",
        "",
        "pair_summary:",
    ]

    for pair, report in pair_reports.items():
        lines.extend([
            f"  {pair}:",
            f"    left_uri_count = {report['left_uri_count']}",
            f"    right_uri_count = {report['right_uri_count']}",
            f"    shared_uri_count = {report['shared_uri_count']}",
            f"    union_uri_count = {report['union_uri_count']}",
            f"    uri_jaccard = {report['uri_jaccard']}",
            f"    semantic_aligned_ratio_on_union = {report['semantic_aligned_ratio_on_union']}",
            f"    classification_counts = {report['classification_counts']}",
        ])

    lines.extend([
        "",
        f"summary_path = {summary_path}",
        "next_stage = " + summary["next_stage"],
    ])

    check_path = out_dir / "checks" / "M16_Batch5_mft_semantic_compare.txt"
    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return summary
