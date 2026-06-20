
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SCHEMA = "sec27.l2b_candidate_effective_input.v1"
REPORT_SCHEMA = "sec27.b3_l2b_effective_input_report.v1"

STATUS_PRESENT = "L2B_EFFECTIVE_SOURCE_URI_PRESENT"
STATUS_NO_SOURCE = "L2B_NO_SOURCE_URI"
STATUS_NOT_COVERED = "L2B_SOURCE_URI_NOT_L2_COVERED"

EVIDENCE_A0 = "A0_UNMAPPED"
EVIDENCE_A1 = "A1_SOURCE_URI_ONLY"
EVIDENCE_A2 = "A2_L2_SOURCE_PP_COVERED"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_jsonl(path: Path, notes: list[str]) -> list[dict[str, Any]]:
    if not path.exists():
        notes.append(f"missing_input:{path}")
        return []

    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                notes.append(f"json_decode_error:{path}:{line_no}:{exc}")
                continue
            if isinstance(obj, dict):
                rows.append(obj)
            else:
                notes.append(f"non_object_jsonl_record:{path}:{line_no}")
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def is_uri(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    v = value.strip().lower()
    return v.startswith(("rsync://", "https://", "http://"))


def unique_sorted(values: list[str]) -> list[str]:
    return sorted({v for v in values if v})


def collect_uris(value: Any) -> list[str]:
    out: list[str] = []
    if is_uri(value):
        return [str(value).strip()]
    if isinstance(value, list):
        for item in value:
            out.extend(collect_uris(item))
    elif isinstance(value, dict):
        for key in [
            "source_uri",
            "sourceUri",
            "uri",
            "roa_uri",
            "roaUri",
            "object_uri",
            "fetch_target_uri",
        ]:
            if key in value:
                out.extend(collect_uris(value.get(key)))
        for key in ["source", "sources", "source_uris", "source_uri_set", "source_uri_sample"]:
            if key in value:
                out.extend(collect_uris(value.get(key)))
    return out


def source_uri_by_probe(record: dict[str, Any]) -> dict[str, list[str]]:
    by_probe: dict[str, list[str]] = defaultdict(list)
    raw = record.get("source_uri_by_probe")

    if isinstance(raw, dict):
        for probe_id, value in raw.items():
            by_probe[str(probe_id)].extend(collect_uris(value))

    direct_uris: list[str] = []
    for key in [
        "source_uri",
        "sourceUri",
        "roa_uri",
        "roaUri",
        "source",
        "sources",
        "source_uris",
        "source_uri_set",
        "source_uri_sample",
        "routinator_jsonext_record",
    ]:
        if key in record:
            direct_uris.extend(collect_uris(record.get(key)))

    if direct_uris and not any(by_probe.values()):
        by_probe["unknown"].extend(direct_uris)

    return {probe: unique_sorted(uris) for probe, uris in by_probe.items() if unique_sorted(uris)}


def get_vrp_key(record: dict[str, Any], source_label: str, index: int) -> str:
    for key in ["vrp_key", "diff_vrp_key", "candidate_vrp_key", "candidate_key", "key"]:
        value = record.get(key)
        if value not in (None, ""):
            return str(value)

    parts = []
    for key in ["tal", "prefix", "asn", "origin_asn", "maxLength", "max_length"]:
        value = record.get(key)
        if value not in (None, ""):
            parts.append(f"{key}={value}")
    if parts:
        return "|".join(parts)
    return f"missing_vrp_key:{source_label}:{index}"


def parse_source_uri(uri: str) -> tuple[str | None, str | None]:
    uri = uri.strip()
    parsed = urlparse(uri)
    if parsed.scheme and parsed.netloc:
        host = parsed.netloc.lower()
        path = parsed.path or "/"
        if path.endswith("/"):
            base_path = path
        else:
            base_path = path.rsplit("/", 1)[0] + "/"
        return host, f"{parsed.scheme.lower()}://{host}{base_path}"

    if "/" in uri:
        base = uri.rsplit("/", 1)[0] + "/"
    else:
        base = uri
    return None, base


def normalize_repo_base(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    _, repo_base = parse_source_uri(value.strip())
    return repo_base


def normalize_host(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    if "://" in value:
        parsed = urlparse(value.strip())
        return parsed.netloc.lower() if parsed.netloc else None
    return value.strip().lower()


def truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "covered"}
    return False


def build_coverage_indexes(rows: list[dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    by_base: dict[str, dict[str, Any]] = {}
    by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for row in rows:
        repo_base = normalize_repo_base(row.get("repo_base") or row.get("repository_base"))
        host = normalize_host(row.get("repo_host")) or normalize_host(repo_base)
        norm = dict(row)
        norm["_repo_base_norm"] = repo_base
        norm["_repo_host_norm"] = host

        if repo_base:
            old = by_base.get(repo_base)
            if old is None or coverage_rank(norm) > coverage_rank(old):
                by_base[repo_base] = norm
        if host:
            by_host[host].append(norm)

    for host, items in list(by_host.items()):
        by_host[host] = sorted(items, key=coverage_rank, reverse=True)

    return by_base, by_host


def coverage_rank(row: dict[str, Any]) -> tuple[int, int, int, str]:
    return (
        1 if truthy(row.get("covered_by_l2")) else 0,
        1 if truthy(row.get("covered_by_l2b")) else 0,
        1 if row.get("mapping_confidence") else 0,
        str(row.get("_repo_base_norm") or row.get("repo_base") or ""),
    )


def find_coverage(
    repo_base: str | None,
    repo_host: str | None,
    by_base: dict[str, dict[str, Any]],
    by_host: dict[str, list[dict[str, Any]]],
) -> tuple[dict[str, Any] | None, str]:
    if repo_base and repo_base in by_base:
        return by_base[repo_base], "exact_repo_base"
    if repo_host and by_host.get(repo_host):
        return by_host[repo_host][0], "fallback_repo_host"
    return None, "missing"


def provenance_union(records: list[tuple[str, dict[str, Any]]]) -> dict[str, dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for index, (source_label, record) in enumerate(records, 1):
        vrp_key = get_vrp_key(record, source_label, index)
        item = grouped.setdefault(
            vrp_key,
            {
                "vrp_key": vrp_key,
                "source_uri_by_probe": defaultdict(set),
                "input_sources": set(),
                "sample_artifacts": set(),
                "tal_values": set(),
            },
        )
        item["input_sources"].add(source_label)
        sample = record.get("sample_artifact") or record.get("artifact") or source_label
        item["sample_artifacts"].add(str(sample))
        tal = record.get("tal") or record.get("rir")
        if tal not in (None, ""):
            item["tal_values"].add(str(tal))

        for probe_id, uris in source_uri_by_probe(record).items():
            for uri in uris:
                item["source_uri_by_probe"][probe_id].add(uri)
    return grouped


def make_missing_record(vrp_key: str, item: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "vrp_key": vrp_key,
        "source_uri": None,
        "repo_host": None,
        "repo_base": None,
        "tal": sorted(item["tal_values"])[0] if item["tal_values"] else None,
        "probe_id": [],
        "probe_presence": {},
        "source_probe_count": 0,
        "source_uri_count_for_vrp": 0,
        "coverage_status": "NO_SOURCE_URI",
        "coverage_match_type": "not_applicable",
        "covered_by_l2": False,
        "covered_by_l2b": False,
        "effective_input_status": STATUS_NO_SOURCE,
        "evidence_level": EVIDENCE_A0,
        "mapping_confidence": "none",
        "temporal_alignment_quality": "unavailable_no_source_uri",
        "causal_claim_allowed": False,
        "sample_artifact": sorted(item["sample_artifacts"]),
        "input_sources": sorted(item["input_sources"]),
    }


def build_effective_input_records(
    grouped: dict[str, dict[str, Any]],
    by_base: dict[str, dict[str, Any]],
    by_host: dict[str, list[dict[str, Any]]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []

    for vrp_key, item in sorted(grouped.items()):
        by_probe_sets: dict[str, set[str]] = item["source_uri_by_probe"]
        all_source_uris = sorted({uri for uris in by_probe_sets.values() for uri in uris})

        if not all_source_uris:
            rec = make_missing_record(vrp_key, item)
            rows.append(rec)
            missing.append(rec)
            continue

        source_uri_count_for_vrp = len(all_source_uris)
        for source_uri in all_source_uris:
            probes = sorted(probe for probe, uris in by_probe_sets.items() if source_uri in uris)
            probe_presence = {probe: (source_uri in uris) for probe, uris in sorted(by_probe_sets.items())}
            source_probe_count = len(probes)
            repo_host, repo_base = parse_source_uri(source_uri)
            coverage, match_type = find_coverage(repo_base, repo_host, by_base, by_host)

            if coverage:
                covered_by_l2 = truthy(coverage.get("covered_by_l2"))
                covered_by_l2b = truthy(coverage.get("covered_by_l2b"))
                coverage_status = str(coverage.get("coverage_status") or "COVERAGE_AVAILABLE")
                mapping_confidence = str(coverage.get("mapping_confidence") or "unknown")
                tal = coverage.get("tal") or (sorted(item["tal_values"])[0] if item["tal_values"] else None)
            else:
                covered_by_l2 = False
                covered_by_l2b = False
                coverage_status = "NOT_COVERED_BY_L2"
                mapping_confidence = "none"
                tal = sorted(item["tal_values"])[0] if item["tal_values"] else None

            if covered_by_l2 or covered_by_l2b:
                effective_input_status = STATUS_PRESENT
            else:
                effective_input_status = STATUS_NOT_COVERED

            if covered_by_l2:
                evidence_level = EVIDENCE_A2
            else:
                evidence_level = EVIDENCE_A1

            if source_probe_count >= 2:
                temporal_alignment_quality = "candidate_window_multi_probe"
            else:
                temporal_alignment_quality = "candidate_window_single_probe"

            rows.append(
                {
                    "schema": SCHEMA,
                    "vrp_key": vrp_key,
                    "source_uri": source_uri,
                    "repo_host": repo_host,
                    "repo_base": repo_base,
                    "tal": tal,
                    "probe_id": probes,
                    "probe_presence": probe_presence,
                    "source_probe_count": source_probe_count,
                    "source_uri_count_for_vrp": source_uri_count_for_vrp,
                    "coverage_status": coverage_status,
                    "coverage_match_type": match_type,
                    "covered_by_l2": covered_by_l2,
                    "covered_by_l2b": covered_by_l2b,
                    "effective_input_status": effective_input_status,
                    "evidence_level": evidence_level,
                    "mapping_confidence": mapping_confidence,
                    "temporal_alignment_quality": temporal_alignment_quality,
                    "causal_claim_allowed": False,
                    "sample_artifact": sorted(item["sample_artifacts"]),
                    "input_sources": sorted(item["input_sources"]),
                }
            )

    return rows, missing


def counter_rows(section: str, rows: list[dict[str, Any]], key: str, limit: int | None = None) -> list[dict[str, Any]]:
    counter = Counter(str(row.get(key) or "unknown") for row in rows)
    items = counter.most_common(limit)
    out = []
    for value, count in items:
        subset = [row for row in rows if str(row.get(key) or "unknown") == value]
        out.append(
            {
                "section": section,
                "value": value,
                "record_count": count,
                "unique_vrp_key_count": len({str(row.get("vrp_key")) for row in subset if row.get("vrp_key")}),
                "unique_source_uri_count": len({str(row.get("source_uri")) for row in subset if row.get("source_uri")}),
            }
        )
    return out


def write_summary_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    table_rows: list[dict[str, Any]] = []
    table_rows.extend(counter_rows("evidence_level", rows, "evidence_level"))
    table_rows.extend(counter_rows("effective_input_status", rows, "effective_input_status"))
    table_rows.extend(counter_rows("temporal_alignment_quality", rows, "temporal_alignment_quality"))
    table_rows.extend(counter_rows("repo_host_top_distribution", rows, "repo_host", limit=20))

    fields = ["section", "value", "record_count", "unique_vrp_key_count", "unique_source_uri_count"]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(table_rows)


def top_vrp_fanout(rows: list[dict[str, Any]], limit: int = 20) -> list[dict[str, Any]]:
    best: dict[str, dict[str, Any]] = {}
    for row in rows:
        vrp_key = row.get("vrp_key")
        if not vrp_key:
            continue
        current = best.setdefault(
            str(vrp_key),
            {
                "vrp_key": str(vrp_key),
                "source_uri_count_for_vrp": int(row.get("source_uri_count_for_vrp") or 0),
                "max_source_probe_count": int(row.get("source_probe_count") or 0),
            },
        )
        current["source_uri_count_for_vrp"] = max(
            int(current["source_uri_count_for_vrp"]),
            int(row.get("source_uri_count_for_vrp") or 0),
        )
        current["max_source_probe_count"] = max(
            int(current["max_source_probe_count"]),
            int(row.get("source_probe_count") or 0),
        )
    return sorted(
        best.values(),
        key=lambda r: (-int(r["source_uri_count_for_vrp"]), -int(r["max_source_probe_count"]), r["vrp_key"]),
    )[:limit]


def build_report(
    args: argparse.Namespace,
    notes: list[str],
    selected_count: int,
    affected_count: int,
    coverage_count: int,
    grouped: dict[str, dict[str, Any]],
    rows: list[dict[str, Any]],
    missing_rows: list[dict[str, Any]],
    output_path: Path,
    missing_path: Path,
    table_path: Path,
) -> dict[str, Any]:
    evidence = Counter(str(row.get("evidence_level") or "unknown") for row in rows)
    status = Counter(str(row.get("effective_input_status") or "unknown") for row in rows)
    temporal = Counter(str(row.get("temporal_alignment_quality") or "unknown") for row in rows)
    host_counter = Counter(str(row.get("repo_host") or "unknown") for row in rows if row.get("repo_host"))

    return {
        "schema": REPORT_SCHEMA,
        "created_at_utc": utc_now(),
        "status": "PASS" if grouped else "NO_INPUT",
        "selected_input_record_count": selected_count,
        "affected_input_record_count": affected_count,
        "coverage_input_record_count": coverage_count,
        "input_candidate_record_count": selected_count + affected_count,
        "output_l2b_record_count": len(rows),
        "unique_vrp_key_count": len({str(row.get("vrp_key")) for row in rows if row.get("vrp_key")}),
        "unique_source_uri_count": len({str(row.get("source_uri")) for row in rows if row.get("source_uri")}),
        "unique_repo_host_count": len({str(row.get("repo_host")) for row in rows if row.get("repo_host")}),
        "missing_source_uri_count": len(missing_rows),
        "covered_by_l2_count": sum(1 for row in rows if row.get("covered_by_l2") is True),
        "not_covered_by_l2_count": sum(1 for row in rows if row.get("covered_by_l2") is not True),
        "evidence_level_distribution": dict(sorted(evidence.items())),
        "effective_input_status_distribution": dict(sorted(status.items())),
        "temporal_alignment_quality_distribution": dict(sorted(temporal.items())),
        "top_repo_hosts": [
            {"repo_host": host, "record_count": count}
            for host, count in host_counter.most_common(20)
        ],
        "top_vrp_fanout": top_vrp_fanout(rows),
        "outputs": {
            "l2b_candidate_effective_input": str(output_path),
            "l2b_candidate_missing_source_uri": str(missing_path),
            "summary_csv": str(table_path),
            "report": str(args.report),
        },
        "notes": notes
        + [
            "B3 normalizes candidate-scoped Routinator source_uri provenance.",
            "B3 does not verify manifest hashes, same-cycle accepted object input, replay, or cross-validator confirmation.",
            "causal_claim_allowed is always false for this task.",
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build SEC27 B3 L2-b effective input candidate records.")
    parser.add_argument("--selected-provenance", required=True)
    parser.add_argument("--affected-provenance", required=True)
    parser.add_argument("--coverage", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--paper-table-dir", required=True)
    parser.add_argument("--report", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    notes: list[str] = []

    selected_path = Path(args.selected_provenance)
    affected_path = Path(args.affected_provenance)
    coverage_path = Path(args.coverage)
    out_dir = Path(args.out_dir)
    table_dir = Path(args.paper_table_dir)
    report_path = Path(args.report)

    selected = read_jsonl(selected_path, notes)
    affected = read_jsonl(affected_path, notes)
    coverage = read_jsonl(coverage_path, notes)

    provenance_records = [("selected_provenance", row) for row in selected]
    provenance_records.extend(("affected_provenance", row) for row in affected)

    grouped = provenance_union(provenance_records)
    coverage_by_base, coverage_by_host = build_coverage_indexes(coverage)
    rows, missing_rows = build_effective_input_records(grouped, coverage_by_base, coverage_by_host)

    output_path = out_dir / "l2b_candidate_effective_input.jsonl"
    missing_path = out_dir / "l2b_candidate_missing_source_uri.jsonl"
    table_path = table_dir / "table_l2b_candidate_effective_input_summary.csv"

    write_jsonl(output_path, rows)
    write_jsonl(missing_path, missing_rows)
    write_summary_csv(table_path, rows)

    report = build_report(
        args=args,
        notes=notes,
        selected_count=len(selected),
        affected_count=len(affected),
        coverage_count=len(coverage),
        grouped=grouped,
        rows=rows,
        missing_rows=missing_rows,
        output_path=output_path,
        missing_path=missing_path,
        table_path=table_path,
    )
    write_json(report_path, report)

    print(f"status = {report['status']}")
    print(f"selected_input_record_count = {report['selected_input_record_count']}")
    print(f"affected_input_record_count = {report['affected_input_record_count']}")
    print(f"input_candidate_record_count = {report['input_candidate_record_count']}")
    print(f"output_l2b_record_count = {report['output_l2b_record_count']}")
    print(f"unique_vrp_key_count = {report['unique_vrp_key_count']}")
    print(f"unique_source_uri_count = {report['unique_source_uri_count']}")
    print(f"missing_source_uri_count = {report['missing_source_uri_count']}")
    print(f"covered_by_l2_count = {report['covered_by_l2_count']}")
    print(f"not_covered_by_l2_count = {report['not_covered_by_l2_count']}")
    print(f"l2b_candidate_effective_input = {output_path}")
    print(f"summary_csv = {table_path}")
    print(f"report = {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
