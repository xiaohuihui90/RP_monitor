#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import gzip
import ipaddress
import json
import os
import shutil
import subprocess
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, TextIO


SCHEMA_INDEX = "s3.probe.rov.jsonext_vrp_provenance_index.v1"
SCHEMA_SUMMARY = "s3.probe.rov.jsonext_vrp_provenance_summary.v1"
ACCEPTANCE_FILE = "checks/P11B2A_JSONEXT_PROVENANCE_INDEX_ACCEPTANCE.txt"

JSONEXT_FILENAMES = [
    "latest_vrps_jsonext.json",
    "jsonext_vrps.json",
    "routinator_jsonext.json",
    "vrps.jsonext.raw.json",
    "latest_vrps_jsonext.json.gz",
    "jsonext_vrps.json.gz",
    "routinator_jsonext.json.gz",
    "vrps.jsonext.raw.json.gz",
]

INDEX_FIELDS = [
    "candidate_vrp_key",
    "asn",
    "prefix",
    "max_length",
    "tal",
    "roa_uri",
    "source_uri",
    "roa_hash",
    "manifest_uri",
    "manifest_hash",
    "manifest_number",
    "manifest_this_update",
    "manifest_next_update",
    "publication_point",
    "ca_repository_uri",
    "rrdp_uri",
    "rsync_uri",
    "validity_not_before",
    "validity_not_after",
    "chain_validity_not_before",
    "chain_validity_not_after",
    "stale",
    "mapping_strength",
    "mapping_reason",
    "mapping_source_file",
    "provenance_source",
    "provenance_time_mode",
    "root_cause_confirmed",
    "causal_claim_allowed",
]

MATCHED_FIELDS = [
    "candidate_vrp_key",
    "asn",
    "prefix",
    "max_length",
    "tal",
    "roa_uri",
    "source_uri",
    "validity_not_before",
    "validity_not_after",
    "chain_validity_not_before",
    "chain_validity_not_after",
    "stale",
    "mapping_strength",
    "mapping_reason",
]

UNRESOLVED_FIELDS = [
    "candidate_vrp_key",
    "asn",
    "prefix",
    "max_length",
    "tal",
    "route_count",
    "present_in_probes",
    "missing_in_probes",
    "mapping_strength",
    "mapping_reason",
]


@dataclass(slots=True)
class Candidate:
    key: str
    asn: str
    prefix: str
    max_length: str
    tal: str
    route_keys: set[str] = field(default_factory=set)
    present_in_probes: set[str] = field(default_factory=set)
    missing_in_probes: set[str] = field(default_factory=set)


def utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def fsync_parent(path: Path) -> None:
    if os.name == "nt":
        return
    fd = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}.{time.time_ns()}")
    try:
        with tmp.open("wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        fsync_parent(path)
    except Exception:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise


def atomic_write_text(path: Path, text: str) -> None:
    atomic_write_bytes(path, text.encode("utf-8"))


def atomic_write_json(path: Path, obj: Any) -> None:
    atomic_write_text(path, json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def resolve_path(value: str | None, root: Path) -> Path | None:
    if not value:
        return None
    path = Path(value).expanduser()
    return path if path.is_absolute() else (root / path).resolve()


def resolve_executable(value: str, root: Path) -> Path:
    expanded = os.path.expanduser(value)
    if any(sep in expanded for sep in ("/", "\\")) or Path(expanded).is_absolute():
        path = Path(expanded)
        return path if path.is_absolute() else (root / path).resolve()
    found = shutil.which(expanded)
    return Path(found) if found else Path(expanded)


def clean(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def parse_bool(value: str | bool) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    raise argparse.ArgumentTypeError(f"expected true or false, got {value}")


def asn_without_as(value: Any) -> str:
    text = clean(value).upper()
    if text.startswith("AS"):
        text = text[2:]
    return text if text.isdigit() else ""


def default_max_length(prefix: str) -> str:
    try:
        return str(ipaddress.ip_network(prefix, strict=False).prefixlen)
    except ValueError:
        return ""


def candidate_key(asn: Any, prefix: Any, max_length: Any, tal: Any) -> str:
    asn_text = asn_without_as(asn)
    prefix_text = clean(prefix)
    max_text = clean(max_length) or default_max_length(prefix_text)
    tal_text = clean(tal).lower()
    if not (asn_text and prefix_text and max_text and tal_text):
        return ""
    return f"{asn_text},{prefix_text},{max_text},{tal_text}"


def parse_candidate_key(key: str) -> tuple[str, str, str, str]:
    parts = [part.strip() for part in clean(key).split(",")]
    if len(parts) != 4:
        return "", "", "", ""
    asn_text = asn_without_as(parts[0])
    return asn_text, parts[1], parts[2], parts[3].lower()


def split_pipe(value: Any) -> set[str]:
    return {part for part in clean(value).split("|") if part}


def add_candidate(candidates: dict[str, Candidate], row: dict[str, Any]) -> None:
    key = clean(row.get("candidate_vrp_key"))
    asn = clean(row.get("candidate_vrp_asn"))
    prefix = clean(row.get("candidate_vrp_prefix"))
    max_length = clean(row.get("candidate_vrp_max_length"))
    tal = clean(row.get("candidate_vrp_tal")).lower()
    if not key:
        key = candidate_key(asn, prefix, max_length, tal)
    if not key:
        return
    if not (asn and prefix and max_length and tal):
        parsed = parse_candidate_key(key)
        asn = asn or parsed[0]
        prefix = prefix or parsed[1]
        max_length = max_length or parsed[2]
        tal = tal or parsed[3]
    item = candidates.setdefault(key, Candidate(key=key, asn=asn, prefix=prefix, max_length=max_length, tal=tal))
    route_key = f"{row.get('route_prefix', '')}|{row.get('origin_asn', '')}"
    if route_key != "|":
        item.route_keys.add(route_key)
    item.present_in_probes.update(split_pipe(row.get("candidate_vrp_present_in_probes")))
    item.missing_in_probes.update(split_pipe(row.get("candidate_vrp_missing_in_probes")))


def load_candidates(p11a_run_dir: Path, max_candidates: int | None) -> tuple[dict[str, Candidate], list[str]]:
    candidates: dict[str, Candidate] = {}
    warnings: list[str] = []
    top_path = p11a_run_dir / "top_candidate_vrps.csv"
    explanations_path = p11a_run_dir / "impact_vrp_explanations.jsonl"
    if top_path.is_file():
        with top_path.open("r", encoding="utf-8-sig", newline="") as f:
            for row in csv.DictReader(f):
                add_candidate(candidates, dict(row))
                if max_candidates is not None and len(candidates) >= max_candidates:
                    return dict(list(candidates.items())[:max_candidates]), warnings
    else:
        warnings.append(f"missing_top_candidate_vrps:{top_path}")
    if explanations_path.is_file():
        with explanations_path.open("r", encoding="utf-8-sig", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    warnings.append("impact_vrp_explanations_parse_error")
                    continue
                if isinstance(row, dict):
                    add_candidate(candidates, row)
                if max_candidates is not None and len(candidates) >= max_candidates:
                    return dict(list(candidates.items())[:max_candidates]), warnings
    else:
        warnings.append(f"missing_impact_vrp_explanations:{explanations_path}")
    return candidates, warnings


def load_json_object(path: Path) -> tuple[dict[str, Any], str | None]:
    try:
        opener = gzip.open if path.suffix.lower() == ".gz" else open
        with opener(path, "rt", encoding="utf-8-sig", errors="replace") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else {"roas": obj if isinstance(obj, list) else []}, None
    except Exception as exc:
        return {}, str(exc)


def candidate_search_roots(manifest_path: Path) -> list[Path]:
    roots = [manifest_path.parent]
    manifest, error = load_json_object(manifest_path)
    if error is None:
        p8_run_dir = clean(manifest.get("p8_run_dir"))
        if p8_run_dir:
            roots.append(Path(p8_run_dir))
        input_root = clean(manifest.get("input_root"))
        if input_root:
            roots.append(Path(input_root))
    out: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        path = root if root.is_absolute() else (repo_root() / root).resolve()
        key = str(path)
        if key not in seen and path.exists():
            out.append(path)
            seen.add(key)
    return out


def find_window_bound_jsonext(manifest_path: Path, probe_id: str | None) -> Path | None:
    for root in candidate_search_roots(manifest_path):
        direct_dirs = [root]
        if probe_id:
            direct_dirs.extend([root / f"probe_id={probe_id}", root / probe_id])
        for directory in direct_dirs:
            for name in JSONEXT_FILENAMES:
                path = directory / name
                if path.is_file() and path.stat().st_size > 0:
                    return path.resolve()
        for name in JSONEXT_FILENAMES:
            matches = sorted(root.rglob(name))
            for path in matches:
                if probe_id and f"probe_id={probe_id}" not in str(path) and probe_id not in str(path):
                    continue
                if path.is_file() and path.stat().st_size > 0:
                    return path.resolve()
    return None


def capture_current_jsonext(routinator_bin: Path, out_dir: Path, timeout_sec: int = 1800) -> dict[str, Any]:
    out_path = out_dir / "current_routinator_jsonext.json"
    tmp_path = out_path.with_suffix(out_path.suffix + f".tmp.{os.getpid()}.{time.time_ns()}")
    result = {
        "attempted": True,
        "ok": False,
        "jsonext_path": str(out_path),
        "command": [],
        "exit_code": None,
        "stderr_tail": "",
        "stdout_tail": "",
        "error": "",
    }
    if not routinator_bin.is_file() and shutil.which(str(routinator_bin)) is None:
        result["error"] = f"routinator_not_found:{routinator_bin}"
        return result
    binary = str(routinator_bin)
    cmd = [binary, "vrps", "--format", "jsonext", "--output", str(tmp_path)]
    result["command"] = cmd
    try:
        proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout_sec)
        result["exit_code"] = proc.returncode
        result["stdout_tail"] = (proc.stdout or "")[-4000:]
        result["stderr_tail"] = (proc.stderr or "")[-4000:]
        if proc.returncode == 0 and tmp_path.is_file() and tmp_path.stat().st_size > 0:
            os.replace(tmp_path, out_path)
            fsync_parent(out_path)
            result["ok"] = True
            return result
    except Exception as exc:
        result["error"] = repr(exc)
    try:
        tmp_path.unlink()
    except FileNotFoundError:
        pass

    cmd_stdout = [binary, "vrps", "--format", "jsonext"]
    result["command"] = cmd_stdout
    try:
        proc = subprocess.run(cmd_stdout, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout_sec)
        result["exit_code"] = proc.returncode
        result["stdout_tail"] = (proc.stdout or "")[-4000:]
        result["stderr_tail"] = (proc.stderr or "")[-4000:]
        if proc.returncode == 0 and proc.stdout:
            atomic_write_text(out_path, proc.stdout)
            result["ok"] = out_path.is_file() and out_path.stat().st_size > 0
    except Exception as exc:
        result["error"] = repr(exc)
    return result


def load_jsonext_roas(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    obj, error = load_json_object(path)
    if error is not None:
        return [], {"jsonext_error": error, "generated_time": ""}
    roas = obj.get("roas", []) if isinstance(obj, dict) else []
    if not isinstance(roas, list):
        roas = []
    metadata = obj.get("metadata") if isinstance(obj.get("metadata"), dict) else {}
    return [row for row in roas if isinstance(row, dict)], {
        "jsonext_error": "",
        "generated_time": metadata.get("generatedTime") or obj.get("generatedTime") or "",
        "metadata": metadata,
    }


def source_list(roa: dict[str, Any]) -> list[dict[str, Any]]:
    source = roa.get("source")
    if isinstance(source, dict):
        return [source]
    if isinstance(source, list):
        return [item for item in source if isinstance(item, dict)]
    return []


def validity_bounds(value: Any) -> tuple[str, str]:
    if not isinstance(value, dict):
        return "", ""
    not_before = clean(value.get("notBefore") or value.get("not_before") or value.get("from") or value.get("valid_from"))
    not_after = clean(value.get("notAfter") or value.get("not_after") or value.get("until") or value.get("valid_until"))
    return not_before, not_after


def repo_base_from_uri(uri: str) -> str:
    text = clean(uri)
    if not text or "/" not in text:
        return ""
    return text.rsplit("/", 1)[0] + "/"


def route_uri_fields(uri: str) -> tuple[str, str]:
    text = clean(uri)
    if text.startswith("rsync://"):
        return "", text
    if text.startswith(("http://", "https://", "rrdp://")):
        return text, ""
    return "", ""


def jsonext_index(roas: list[dict[str, Any]], jsonext_path: Path, provenance_time_mode: str) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    index: dict[str, list[dict[str, Any]]] = {}
    counters: Counter[str] = Counter()
    by_tal: Counter[str] = Counter()
    by_source_type: Counter[str] = Counter()
    for roa in roas:
        try:
            asn = asn_without_as(roa.get("asn"))
            prefix = clean(roa.get("prefix"))
            max_length = clean(roa.get("maxLength") or roa.get("max_length")) or default_max_length(prefix)
        except Exception:
            counters["invalid_roa_tuple"] += 1
            continue
        if not (asn and prefix and max_length):
            counters["invalid_roa_tuple"] += 1
            continue
        sources = source_list(roa)
        if not sources:
            counters["roa_without_source"] += 1
        for src in sources:
            source_type = clean(src.get("type") or "unknown").lower()
            by_source_type[source_type] += 1
            if source_type and source_type != "roa":
                counters["non_roa_source_skipped"] += 1
                continue
            tal = clean(src.get("tal") or roa.get("tal") or roa.get("ta")).lower()
            if not tal:
                counters["source_without_tal"] += 1
                continue
            uri = clean(src.get("uri"))
            key = candidate_key(asn, prefix, max_length, tal)
            validity_from, validity_to = validity_bounds(src.get("validity"))
            chain_from, chain_to = validity_bounds(src.get("chainValidity"))
            rrdp_uri, rsync_uri = route_uri_fields(uri)
            row = {
                "candidate_vrp_key": key,
                "asn": asn,
                "prefix": prefix,
                "max_length": max_length,
                "tal": tal,
                "roa_uri": uri,
                "source_uri": uri,
                "roa_hash": "",
                "manifest_uri": "",
                "manifest_hash": "",
                "manifest_number": "",
                "manifest_this_update": "",
                "manifest_next_update": "",
                "publication_point": repo_base_from_uri(uri),
                "ca_repository_uri": repo_base_from_uri(uri),
                "rrdp_uri": rrdp_uri,
                "rsync_uri": rsync_uri,
                "validity_not_before": validity_from,
                "validity_not_after": validity_to,
                "chain_validity_not_before": chain_from,
                "chain_validity_not_after": chain_to,
                "stale": src.get("stale", ""),
                "mapping_strength": "medium" if uri else "weak",
                "mapping_reason": "jsonext_roa_source_uri" if uri else "jsonext_tal_only",
                "mapping_source_file": str(jsonext_path),
                "provenance_source": "jsonext",
                "provenance_time_mode": provenance_time_mode,
                "root_cause_confirmed": False,
                "causal_claim_allowed": False,
            }
            index.setdefault(key, []).append(row)
            by_tal[tal] += 1
            counters["jsonext_source_index_rows"] += 1
    return index, {
        "counters": dict(counters),
        "by_tal": dict(sorted(by_tal.items())),
        "by_source_type": dict(sorted(by_source_type.items())),
    }


def open_tmp_text(path: Path) -> tuple[Path, TextIO]:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}.{time.time_ns()}")
    return tmp, tmp.open("w", encoding="utf-8", newline="\n")


def publish_tmp(tmp: Path, path: Path) -> None:
    os.replace(tmp, path)
    fsync_parent(path)


def write_csv_atomic(path: Path, fields: list[str], rows: list[dict[str, Any]]) -> None:
    tmp, f = open_tmp_text(path)
    try:
        with f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow({field: row.get(field, "") for field in fields})
            f.flush()
            os.fsync(f.fileno())
        publish_tmp(tmp, path)
    except Exception:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise


def unmatched_row(candidate: Candidate, mapping_reason: str, provenance_time_mode: str, jsonext_path: str) -> dict[str, Any]:
    return {
        "candidate_vrp_key": candidate.key,
        "asn": candidate.asn,
        "prefix": candidate.prefix,
        "max_length": candidate.max_length,
        "tal": candidate.tal,
        "roa_uri": "",
        "source_uri": "",
        "roa_hash": "",
        "manifest_uri": "",
        "manifest_hash": "",
        "manifest_number": "",
        "manifest_this_update": "",
        "manifest_next_update": "",
        "publication_point": "",
        "ca_repository_uri": "",
        "rrdp_uri": "",
        "rsync_uri": "",
        "validity_not_before": "",
        "validity_not_after": "",
        "chain_validity_not_before": "",
        "chain_validity_not_after": "",
        "stale": "",
        "mapping_strength": "none",
        "mapping_reason": mapping_reason,
        "mapping_source_file": jsonext_path,
        "provenance_source": "jsonext",
        "provenance_time_mode": provenance_time_mode,
        "root_cause_confirmed": False,
        "causal_claim_allowed": False,
    }


def write_acceptance(out_dir: Path, status: str, summary: dict[str, Any], checks: dict[str, bool]) -> None:
    lines = [
        f"P11B2A_JSONEXT_PROVENANCE_INDEX={status}",
        f"candidate_vrp_count={summary.get('candidate_vrp_count', 0)}",
        f"jsonext_loaded_or_generated={str(summary.get('jsonext_loaded_or_generated', False)).lower()}",
        f"mapped_candidate_vrp_count={summary.get('mapped_candidate_vrp_count', 0)}",
        f"unresolved_candidate_vrp_count={summary.get('unresolved_candidate_vrp_count', 0)}",
        f"provenance_time_mode={summary.get('provenance_time_mode', '')}",
        f"jsonext_file={summary.get('jsonext_file', '')}",
        f"mapping_index_jsonl={summary.get('outputs', {}).get('vrp_object_mapping_index_jsonl', '')}",
        "",
        "[checks]",
    ]
    lines.extend(f"{key}={str(value).lower()}" for key, value in checks.items())
    atomic_write_text(out_dir / ACCEPTANCE_FILE, "\n".join(lines) + "\n")


def run(args: argparse.Namespace) -> int:
    root = repo_root()
    started_at = utc_now()
    started = time.monotonic()
    p11a_run_dir = resolve_path(args.p11a_run_dir, root)
    manifest_path = resolve_path(args.p8_input_vrp_manifest, root)
    out_dir = resolve_path(args.out_dir, root)
    if p11a_run_dir is None or manifest_path is None or out_dir is None:
        raise SystemExit("required paths are missing")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "checks").mkdir(parents=True, exist_ok=True)

    candidates, candidate_warnings = load_candidates(p11a_run_dir, args.max_candidates)
    p11a_readable = (p11a_run_dir / "top_candidate_vrps.csv").is_file() or (p11a_run_dir / "impact_vrp_explanations.jsonl").is_file()

    jsonext_path = resolve_path(args.jsonext_file, root)
    jsonext_source = "explicit" if jsonext_path and jsonext_path.is_file() else ""
    provenance_time_mode = "window_bound"
    capture_result: dict[str, Any] = {"attempted": False, "ok": False}
    if jsonext_path is None and parse_bool(args.use_window_bound_jsonext_if_available):
        jsonext_path = find_window_bound_jsonext(manifest_path, args.probe_id)
        jsonext_source = "window_bound_search" if jsonext_path else ""
    if jsonext_path is None or not jsonext_path.is_file():
        routinator_bin = resolve_executable(args.routinator_bin, root)
        provenance_time_mode = "current_not_window_bound"
        capture_result = capture_current_jsonext(routinator_bin, out_dir)
        if capture_result.get("ok"):
            jsonext_path = Path(str(capture_result["jsonext_path"]))
            jsonext_source = "current_routinator_command"
    elif jsonext_source == "explicit":
        search_roots = candidate_search_roots(manifest_path)
        if any(str(jsonext_path).startswith(str(search_root)) for search_root in search_roots):
            provenance_time_mode = "window_bound"
        else:
            provenance_time_mode = "current_not_window_bound"

    roas: list[dict[str, Any]] = []
    jsonext_meta: dict[str, Any] = {}
    if jsonext_path is not None and jsonext_path.is_file():
        roas, jsonext_meta = load_jsonext_roas(jsonext_path)
    jsonext_loaded_or_generated = bool(roas)
    source_index, index_stats = jsonext_index(roas, jsonext_path or Path(""), provenance_time_mode) if roas else ({}, {"counters": {}, "by_tal": {}, "by_source_type": {}})

    index_tmp, index_f = open_tmp_text(out_dir / "vrp_object_mapping_index.jsonl")
    csv_tmp, csv_f = open_tmp_text(out_dir / "vrp_object_mapping_index.csv")
    matched_rows: list[dict[str, Any]] = []
    unresolved_rows: list[dict[str, Any]] = []
    mapped_candidates: set[str] = set()
    try:
        with index_f, csv_f:
            writer = csv.DictWriter(csv_f, fieldnames=INDEX_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for candidate in candidates.values():
                matches = source_index.get(candidate.key, [])
                if matches:
                    mapped_candidates.add(candidate.key)
                    for row in matches:
                        index_f.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
                        writer.writerow({field: row.get(field, "") for field in INDEX_FIELDS})
                        matched_rows.append(row)
                else:
                    reason = "NO_JSONEXT_AVAILABLE" if not jsonext_loaded_or_generated else "NO_JSONEXT_SOURCE_MATCH"
                    row = unmatched_row(candidate, reason, provenance_time_mode, str(jsonext_path or ""))
                    index_f.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
                    writer.writerow({field: row.get(field, "") for field in INDEX_FIELDS})
                    unresolved_rows.append({
                        "candidate_vrp_key": candidate.key,
                        "asn": candidate.asn,
                        "prefix": candidate.prefix,
                        "max_length": candidate.max_length,
                        "tal": candidate.tal,
                        "route_count": len(candidate.route_keys),
                        "present_in_probes": "|".join(sorted(candidate.present_in_probes)),
                        "missing_in_probes": "|".join(sorted(candidate.missing_in_probes)),
                        "mapping_strength": "none",
                        "mapping_reason": reason,
                    })
            index_f.flush()
            os.fsync(index_f.fileno())
            csv_f.flush()
            os.fsync(csv_f.fileno())
        publish_tmp(index_tmp, out_dir / "vrp_object_mapping_index.jsonl")
        publish_tmp(csv_tmp, out_dir / "vrp_object_mapping_index.csv")
    except Exception:
        for tmp in (index_tmp, csv_tmp):
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass
        raise

    write_csv_atomic(out_dir / "matched_candidate_vrps.csv", MATCHED_FIELDS, matched_rows)
    write_csv_atomic(out_dir / "unresolved_candidate_vrps.csv", UNRESOLVED_FIELDS, unresolved_rows)

    outputs_written = all(
        (out_dir / name).is_file()
        for name in [
            "vrp_object_mapping_index.jsonl",
            "vrp_object_mapping_index.csv",
            "matched_candidate_vrps.csv",
            "unresolved_candidate_vrps.csv",
        ]
    )
    checks = {
        "candidate_vrp_count_gt_zero": len(candidates) > 0,
        "jsonext_loaded_or_generated": jsonext_loaded_or_generated,
        "index_written": (out_dir / "vrp_object_mapping_index.jsonl").is_file(),
        "mapped_candidate_vrp_count_gt_zero": len(mapped_candidates) > 0,
        "outputs_written": outputs_written,
        "no_strong_root_cause_claim": True,
    }
    if not p11a_readable or not candidates or not outputs_written:
        status = "FAIL"
    elif checks["jsonext_loaded_or_generated"] and checks["mapped_candidate_vrp_count_gt_zero"]:
        status = "PASS"
    else:
        status = "PASS_WITH_EXCLUSIONS"

    summary = {
        "schema": SCHEMA_SUMMARY,
        "status": status,
        "p11a_run_dir": str(p11a_run_dir),
        "p8_input_vrp_manifest": str(manifest_path),
        "out_dir": str(out_dir),
        "candidate_vrp_count": len(candidates),
        "mapped_candidate_vrp_count": len(mapped_candidates),
        "unresolved_candidate_vrp_count": len(unresolved_rows),
        "jsonext_loaded_or_generated": jsonext_loaded_or_generated,
        "jsonext_file": str(jsonext_path or ""),
        "jsonext_source": jsonext_source,
        "jsonext_generated_time": jsonext_meta.get("generated_time", ""),
        "jsonext_roa_record_count": len(roas),
        "provenance_time_mode": provenance_time_mode,
        "capture_current_jsonext_result": capture_result,
        "candidate_warnings": candidate_warnings,
        "jsonext_index_stats": index_stats,
        "root_cause_confirmed": False,
        "causal_claim_allowed": False,
        "started_at_utc": started_at,
        "finished_at_utc": utc_now(),
        "duration_sec": round(time.monotonic() - started, 6),
        "outputs": {
            "vrp_object_mapping_index_jsonl": str(out_dir / "vrp_object_mapping_index.jsonl"),
            "vrp_object_mapping_index_csv": str(out_dir / "vrp_object_mapping_index.csv"),
            "matched_candidate_vrps_csv": str(out_dir / "matched_candidate_vrps.csv"),
            "unresolved_candidate_vrps_csv": str(out_dir / "unresolved_candidate_vrps.csv"),
            "jsonext_parse_summary": str(out_dir / "jsonext_parse_summary.json"),
            "acceptance_check_file": str(out_dir / ACCEPTANCE_FILE),
        },
        "checks": checks,
    }
    atomic_write_json(out_dir / "jsonext_parse_summary.json", summary)
    write_acceptance(out_dir, status, summary, checks)
    return 0 if status in {"PASS", "PASS_WITH_EXCLUSIONS"} else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a P11-B-compatible candidate VRP provenance index from Routinator jsonext.")
    parser.add_argument("--p11a-run-dir", required=True)
    parser.add_argument("--p8-input-vrp-manifest", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--routinator-bin", default="~/.cargo/bin/routinator")
    parser.add_argument("--jsonext-file")
    parser.add_argument("--probe-id")
    parser.add_argument("--max-candidates", type=int)
    parser.add_argument("--use-window-bound-jsonext-if-available", type=parse_bool, default=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
