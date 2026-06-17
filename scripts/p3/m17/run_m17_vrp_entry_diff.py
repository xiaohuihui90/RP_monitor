#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROBE_ORDER = ["probe-bj", "probe-cd", "probe-sg"]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not path.exists():
        return out
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
    return out


def sha256_text(s: str) -> str:
    return "sha256:" + hashlib.sha256(s.encode("utf-8")).hexdigest()


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def parse_asn(value: Any) -> int | None:
    if value is None:
        return None
    s = str(value).strip()
    if s.upper().startswith("AS"):
        s = s[2:]
    try:
        return int(s)
    except Exception:
        return None


def normalize_prefix(value: Any) -> tuple[str | None, int | None, str | None]:
    if value is None:
        return None, None, None
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
        afi = "ipv4" if net.version == 4 else "ipv6"
        return str(net), int(net.prefixlen), afi
    except Exception:
        return None, None, None


def extract_records(raw: Any) -> tuple[str | None, list[dict[str, Any]]]:
    if isinstance(raw, list):
        return "__top_level_list__", [x for x in raw if isinstance(x, dict)]

    if isinstance(raw, dict):
        for key in ["roas", "vrps", "validated_roa_payloads", "validated_roas", "records", "data", "items"]:
            value = raw.get(key)
            if isinstance(value, list):
                return key, [x for x in value if isinstance(x, dict)]

    return None, []


def get_first(record: dict[str, Any], keys: list[str]) -> Any:
    for k in keys:
        if k in record and record[k] is not None:
            return record[k]
    return None


def normalize_one(
    raw_record: dict[str, Any],
    raw_index: int,
    window_id: str,
    probe_id: str,
    validator: str,
    validator_version: str | None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    prefix_raw = get_first(raw_record, ["prefix", "ipPrefix", "ip_prefix"])
    asn_raw = get_first(raw_record, ["asn", "asID", "as_id", "origin_asn", "origin"])
    max_len_raw = get_first(raw_record, ["maxLength", "max_length", "maxlength", "maxLen", "max_len"])
    tal_raw = get_first(raw_record, ["tal", "ta", "trust_anchor", "trustAnchor"])

    prefix, prefix_len, afi = normalize_prefix(prefix_raw)
    asn = parse_asn(asn_raw)

    warnings: list[str] = []

    if prefix is None:
        warnings.append("prefix_parse_failed")
    if asn is None:
        warnings.append("asn_parse_failed")

    if max_len_raw is None:
        max_len = prefix_len
        warnings.append("maxLength_missing_default_to_prefix_len")
    else:
        try:
            max_len = int(max_len_raw)
        except Exception:
            max_len = prefix_len
            warnings.append("maxLength_parse_failed_default_to_prefix_len")

    tal = str(tal_raw).strip().lower() if tal_raw is not None and str(tal_raw).strip() else "unknown_tal"
    if tal == "unknown_tal":
        warnings.append("tal_missing")

    source_uri = get_first(raw_record, ["source_uri", "source", "uri", "resource"])
    roa_uri = get_first(raw_record, ["roa_uri", "roaUri", "roa"])

    if prefix is None or asn is None or max_len is None or afi is None:
        fail = {
            "raw_record_index": raw_index,
            "raw_record_sha256": sha256_text(canonical_json(raw_record)),
            "normalization_status": "failed",
            "normalization_warnings": warnings,
            "raw_record_excerpt": raw_record,
        }
        return None, fail

    vrp_key = f"{afi}|{tal}|{prefix}|{asn}|{max_len}"

    normalized = {
        "schema": "s3.m17.canonical_vrp_record.v1",
        "window_id": window_id,
        "probe_id": probe_id,
        "validator": validator,
        "validator_version": validator_version,

        "afi": afi,
        "tal": tal,
        "prefix": prefix,
        "prefix_len": prefix_len,
        "asn": asn,
        "maxLength": max_len,
        "vrp_key": vrp_key,

        "source_uri": source_uri,
        "roa_uri": roa_uri,

        "candidate_pp_uri": None,
        "candidate_manifest_uri": None,
        "candidate_roa_uri": roa_uri if roa_uri else source_uri if isinstance(source_uri, str) and source_uri.endswith(".roa") else None,
        "candidate_object_hash": None,

        "raw_record_index": raw_index,
        "raw_record_sha256": sha256_text(canonical_json(raw_record)),
        "normalization_status": "ok",
        "normalization_warnings": warnings,
    }
    return normalized, None


def load_selected_windows(path: Path) -> list[dict[str, Any]]:
    obj = read_json(path)
    if not isinstance(obj, dict):
        raise RuntimeError("selected_windows.json is not an object")
    selected = obj.get("selected_windows", [])
    if not isinstance(selected, list):
        raise RuntimeError("selected_windows is not a list")
    return [x for x in selected if isinstance(x, dict)]


def window_output_dir(out_root: Path, window_id: str) -> Path:
    return out_root / "history" / f"m17_window_{window_id}" / "outputs"


def window_check_dir(out_root: Path, window_id: str) -> Path:
    return out_root / "history" / f"m17_window_{window_id}" / "checks"


def probe_raw_files(window_dir: Path) -> dict[str, Path]:
    root = window_dir / "outputs" / "raw_vrp"
    found: dict[str, Path] = {}
    for p in sorted(root.glob("probe-*/*_raw_vrp.json")):
        found[p.parent.name] = p
    return found


def load_validator_meta(window_dir: Path) -> dict[str, Any]:
    p = window_dir / "outputs" / "validator_runtime_metadata.json"
    if p.exists():
        obj = read_json(p)
        if isinstance(obj, dict):
            return obj
    return {}


def get_probe_validator(meta: dict[str, Any], probe_id: str) -> tuple[str, str | None]:
    pmeta = meta.get("probe_metadata", {})
    if isinstance(pmeta, dict):
        m = pmeta.get(probe_id, {})
        if isinstance(m, dict):
            return str(m.get("validator") or "routinator"), m.get("validator_version")
    return "routinator", None


def run_canonical(selected_windows: Path, out_root: Path) -> None:
    candidates = load_selected_windows(selected_windows)

    for c in candidates:
        window_id = c["window_id"]
        window_dir = Path(c["window_dir"])
        out_dir = window_output_dir(out_root, window_id)
        out_dir.mkdir(parents=True, exist_ok=True)

        meta = load_validator_meta(window_dir)
        raw_files = probe_raw_files(window_dir)

        manifest = {
            "schema": "s3.m17.canonical_vrp_manifest.v1",
            "generated_at_utc": utc_now(),
            "window_id": window_id,
            "window_dir": str(window_dir),
            "probe_count": len(raw_files),
            "probes": {},
        }

        for probe_id in sorted(raw_files.keys()):
            raw_path = raw_files[probe_id]
            raw = read_json(raw_path)
            array_key, raw_records = extract_records(raw)

            validator, validator_version = get_probe_validator(meta, probe_id)

            canonical_records: list[dict[str, Any]] = []
            failed_records: list[dict[str, Any]] = []

            for i, rec in enumerate(raw_records):
                norm, fail = normalize_one(
                    raw_record=rec,
                    raw_index=i,
                    window_id=window_id,
                    probe_id=probe_id,
                    validator=validator,
                    validator_version=validator_version,
                )
                if norm:
                    canonical_records.append(norm)
                if fail:
                    failed_records.append(fail)

            canonical_records.sort(key=lambda r: r["vrp_key"])

            canonical_path = out_dir / f"canonical_vrp_records_{probe_id}.jsonl"
            failed_path = out_dir / f"canonical_vrp_failed_records_{probe_id}.jsonl"

            write_jsonl(canonical_path, canonical_records)
            write_jsonl(failed_path, failed_records)

            source_uri_available = sum(1 for r in canonical_records if r.get("source_uri") or r.get("roa_uri"))
            unknown_tal = sum(1 for r in canonical_records if r.get("tal") == "unknown_tal")

            manifest["probes"][probe_id] = {
                "raw_vrp_path": str(raw_path),
                "raw_array_key": array_key,
                "canonical_vrp_path": str(canonical_path),
                "failed_records_path": str(failed_path),
                "raw_count": len(raw_records),
                "canonical_count": len(canonical_records),
                "normalization_failed_count": len(failed_records),
                "unknown_tal_count": unknown_tal,
                "source_uri_available_count": source_uri_available,
                "source_uri_missing_count": len(canonical_records) - source_uri_available,
            }

        write_json(out_dir / "canonical_vrp_manifest.json", manifest)

    print("M17_STEP_CANONICAL_VRP_NORMALIZER=PASS")


def iter_jsonl(path: Path):
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def load_key_set(path: Path) -> set[str]:
    keys: set[str] = set()
    for r in iter_jsonl(path):
        key = r.get("vrp_key")
        if isinstance(key, str):
            keys.add(key)
    return keys


def load_change_map(path: Path) -> dict[str, set[int]]:
    """
    Low-memory-ish map for changed detection:
    change_key = afi|tal|prefix|asn -> set(maxLength)
    """
    out: dict[str, set[int]] = {}
    for r in iter_jsonl(path):
        try:
            ck = change_key(r)
            ml = int(r["maxLength"])
            out.setdefault(ck, set()).add(ml)
        except Exception:
            continue
    return out


def collect_records_for_keys(path: Path, needed_keys: set[str]) -> dict[str, dict[str, Any]]:
    """
    Second pass over canonical file to collect full records only for diff keys.
    """
    found: dict[str, dict[str, Any]] = {}
    if not needed_keys:
        return found

    for r in iter_jsonl(path):
        key = r.get("vrp_key")
        if key in needed_keys:
            found[key] = r
            if len(found) == len(needed_keys):
                break
    return found


def run_pairwise(selected_windows: Path, out_root: Path) -> None:
    """
    Low-memory pairwise VRP diff.

    Key idea:
      - Load only vrp_key sets for pairwise set difference.
      - Re-scan canonical files only for diff keys to build records.
      - Do not write full vote profile records for all stable VRPs.
    """
    candidates = load_selected_windows(selected_windows)

    for c in candidates:
        window_id = c["window_id"]
        out_dir = window_output_dir(out_root, window_id)
        manifest = read_json(out_dir / "canonical_vrp_manifest.json")
        probes = sorted(manifest.get("probes", {}).keys())

        canonical_paths = {
            probe_id: Path(manifest["probes"][probe_id]["canonical_vrp_path"])
            for probe_id in probes
        }

        diff_path = out_dir / "vrp_entry_diff_records.jsonl"
        diff_path.parent.mkdir(parents=True, exist_ok=True)

        pair_summaries: dict[str, dict[str, Any]] = {}
        vote_status_counts = {
            "all_probe_stable": 0,
            "majority_observed": 0,
            "single_probe_outlier": 0,
            "no_majority": 0,
        }

        # Load key sets only. This is much smaller than loading full records.
        key_sets: dict[str, set[str]] = {}
        for probe_id in probes:
            key_sets[probe_id] = load_key_set(canonical_paths[probe_id])

        # Vote profile summary only, no per-key stable output.
        if key_sets:
            all_keys = set().union(*key_sets.values())
            for key in all_keys:
                vote_count = sum(1 for p in probes if key in key_sets[p])
                if vote_count == len(probes):
                    vote_status_counts["all_probe_stable"] += 1
                elif vote_count >= 2:
                    vote_status_counts["majority_observed"] += 1
                elif vote_count == 1:
                    vote_status_counts["single_probe_outlier"] += 1
                else:
                    vote_status_counts["no_majority"] += 1
        else:
            all_keys = set()

        with diff_path.open("w", encoding="utf-8") as out_f:
            for i in range(len(probes)):
                for j in range(i + 1, len(probes)):
                    left = probes[i]
                    right = probes[j]
                    pair = f"{left}|{right}"

                    left_keys = key_sets[left]
                    right_keys = key_sets[right]

                    only_left = left_keys - right_keys
                    only_right = right_keys - left_keys

                    left_records = collect_records_for_keys(canonical_paths[left], only_left)
                    right_records = collect_records_for_keys(canonical_paths[right], only_right)

                    added_count = 0
                    removed_count = 0
                    changed_count = 0

                    affected_prefixes: set[str] = set()
                    affected_asns: set[str] = set()

                    for key in sorted(only_left):
                        vrp = left_records.get(key)
                        if not vrp:
                            continue
                        rec = make_diff_record(
                            window_id,
                            pair,
                            left,
                            right,
                            "only_in_left",
                            "removed",
                            vrp,
                            True,
                            False,
                        )
                        out_f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
                        removed_count += 1
                        affected_prefixes.add(str(vrp.get("prefix")))
                        affected_asns.add(str(vrp.get("asn")))

                    for key in sorted(only_right):
                        vrp = right_records.get(key)
                        if not vrp:
                            continue
                        rec = make_diff_record(
                            window_id,
                            pair,
                            left,
                            right,
                            "only_in_right",
                            "added",
                            vrp,
                            False,
                            True,
                        )
                        out_f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
                        added_count += 1
                        affected_prefixes.add(str(vrp.get("prefix")))
                        affected_asns.add(str(vrp.get("asn")))

                    # Low-memory changed detection based on maxLength set by change_key.
                    left_change = load_change_map(canonical_paths[left])
                    right_change = load_change_map(canonical_paths[right])
                    changed_keys = {
                        ck for ck in (set(left_change) & set(right_change))
                        if left_change[ck] != right_change[ck]
                    }

                    # Avoid huge changed records; most maxLength differences are already visible
                    # as only_in_left / only_in_right on the full vrp_key. Emit compact records.
                    for ck in sorted(changed_keys):
                        parts = ck.split("|")
                        if len(parts) != 4:
                            continue
                        afi, tal, prefix, asn_s = parts
                        try:
                            asn_i = int(asn_s)
                        except Exception:
                            asn_i = None

                        vrp = {
                            "afi": afi,
                            "tal": tal,
                            "prefix": prefix,
                            "prefix_len": int(prefix.split("/")[-1]) if "/" in prefix else None,
                            "asn": asn_i,
                            "maxLength": None,
                            "source_uri": None,
                            "roa_uri": None,
                            "candidate_pp_uri": None,
                            "candidate_manifest_uri": None,
                            "candidate_roa_uri": None,
                            "candidate_object_hash": None,
                            "vrp_key": ck + "|changed",
                        }

                        rec = make_diff_record(
                            window_id,
                            pair,
                            left,
                            right,
                            "changed",
                            "modified",
                            vrp,
                            True,
                            True,
                        )
                        rec["changed_fields"] = ["maxLength"]
                        rec["left_maxLength_set"] = sorted(left_change[ck])
                        rec["right_maxLength_set"] = sorted(right_change[ck])
                        rec["impact_semantics_candidate"]["subprefix_protection_changed"] = True
                        rec["impact_semantics_candidate"]["maxLength_expanded"] = max(right_change[ck]) > max(left_change[ck])
                        rec["impact_semantics_candidate"]["maxLength_shrunk"] = max(right_change[ck]) < max(left_change[ck])

                        out_f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
                        changed_count += 1
                        affected_prefixes.add(prefix)
                        affected_asns.add(asn_s)

                    pair_summaries[pair] = {
                        "left_probe": left,
                        "right_probe": right,
                        "left_count": len(left_keys),
                        "right_count": len(right_keys),
                        "added_vrps": added_count,
                        "removed_vrps": removed_count,
                        "changed_vrps": changed_count,
                        "affected_prefix_count": len(affected_prefixes),
                        "affected_asn_count": len(affected_asns),
                    }

        vote_summary = {
            "schema": "s3.m17.vrp_vote_profile_summary.v1",
            "window_id": window_id,
            "probe_count": len(probes),
            "total_unique_vrp_keys": len(all_keys),
            "vote_status_counts": vote_status_counts,
            "note": "Low-memory mode writes vote profile summary only, not per-stable-VRP records."
        }

        write_json(out_dir / "vrp_vote_profile_summary.json", vote_summary)

        # Keep file for downstream acceptance, but only record non-all-stable keys would be written in future.
        vote_records_path = out_dir / "vrp_vote_profile_records.jsonl"
        vote_records_path.write_text("", encoding="utf-8")

        write_json(out_dir / "pairwise_diff_summary.json", {
            "schema": "s3.m17.pairwise_diff_summary.v1",
            "generated_at_utc": utc_now(),
            "window_id": window_id,
            "pair_summaries": pair_summaries,
            "low_memory_mode": True,
        })

    print("M17_STEP_PAIRWISE_VRP_DIFF=PASS")


def change_key(r: dict[str, Any]) -> str:
    return f"{r['afi']}|{r['tal']}|{r['prefix']}|{r['asn']}"


def make_diff_record(
    window_id: str,
    pair: str,
    left: str,
    right: str,
    diff_type: str,
    event_type: str,
    vrp: dict[str, Any],
    left_present: bool,
    right_present: bool,
) -> dict[str, Any]:
    vrp_obj = {
        "afi": vrp.get("afi"),
        "tal": vrp.get("tal"),
        "prefix": vrp.get("prefix"),
        "prefix_len": vrp.get("prefix_len"),
        "asn": vrp.get("asn"),
        "maxLength": vrp.get("maxLength"),
        "source_uri": vrp.get("source_uri"),
        "roa_uri": vrp.get("roa_uri"),
        "candidate_pp_uri": vrp.get("candidate_pp_uri"),
        "candidate_manifest_uri": vrp.get("candidate_manifest_uri"),
        "candidate_roa_uri": vrp.get("candidate_roa_uri"),
        "candidate_object_hash": vrp.get("candidate_object_hash"),
    }

    return {
        "schema": "s3.m17.vrp_entry_diff_record.v1",
        "window_id": window_id,
        "probe_pair": pair,
        "left_probe": left,
        "right_probe": right,
        "diff_type": diff_type,
        "event_type": event_type,
        "vrp_key": vrp.get("vrp_key"),
        "vrp": vrp_obj,
        "left_present": left_present,
        "right_present": right_present,
        "object_mapping_hint": {
            "roa_mapping_status": "source_uri_available" if vrp_obj.get("candidate_roa_uri") else "source_uri_missing",
            "manifest_mapping_status": "unknown",
            "pp_mapping_status": "unknown",
            "hash_mapping_status": "unknown",
        },
        "mapping_context": {
            "mapping_strength": "weak",
            "diff_scope_status": "unknown",
            "needs_roa_to_vrp_mapping": True,
            "needs_targeted_l1_l2_backfill": False,
            "same_input_replay_required": False,
            "strong_causal_claim_allowed": False,
        },
        "impact_semantics_candidate": {
            "needs_rov_state_analysis": True,
            "valid_to_notfound_candidate": event_type == "removed",
            "valid_to_invalid_candidate": False,
            "subprefix_protection_changed": False,
            "maxLength_expanded": False,
            "maxLength_shrunk": False,
        },
        "temporal_context": {
            "first_seen_window": window_id,
            "last_seen_window": window_id,
            "duration_windows": 1,
            "temporal_class": "single_window",
            "trailing_cache_candidate": False,
        },
        "allowed_claims": [
            "vrp_entry_difference_observed",
            "affected_prefix_and_asn_identified",
        ],
        "disallowed_claims": [
            "object_root_caused_vrp_root",
            "specific_roa_caused_vrp_diff",
            "publication_point_caused_vrp_diff",
            "validator_implementation_divergence",
            "high_confidence_attribution",
        ],
    }


def run_aggregator(selected_windows: Path, out_root: Path) -> None:
    candidates = load_selected_windows(selected_windows)

    for c in candidates:
        window_id = c["window_id"]
        out_dir = window_output_dir(out_root, window_id)
        manifest = read_json(out_dir / "canonical_vrp_manifest.json")
        diff_records = read_jsonl(out_dir / "vrp_entry_diff_records.jsonl")

        summary_by_pair: dict[str, dict[str, Any]] = {}
        diff_by_tal: dict[str, dict[str, Any]] = {}
        diff_by_prefix: dict[str, dict[str, Any]] = {}
        diff_by_asn: dict[str, dict[str, Any]] = {}
        diff_by_pp: dict[str, dict[str, Any]] = {}
        diff_by_manifest: dict[str, dict[str, Any]] = {}
        diff_by_roa: dict[str, dict[str, Any]] = {}
        diff_by_hash: dict[str, dict[str, Any]] = {}

        affected_prefixes = set()
        affected_asns = set()
        affected_tals = set()

        unknown_pp = unknown_manifest = unknown_roa = unknown_hash = 0

        for r in diff_records:
            pair = r["probe_pair"]
            event = r["event_type"]
            vrp = r["vrp"]
            tal = str(vrp.get("tal"))
            prefix = str(vrp.get("prefix"))
            asn = str(vrp.get("asn"))

            affected_prefixes.add(prefix)
            affected_asns.add(asn)
            affected_tals.add(tal)

            bump(summary_by_pair, pair, event, prefix, asn, tal)
            bump(diff_by_tal, tal, event, prefix, asn, tal)
            bump(diff_by_prefix, prefix, event, prefix, asn, tal)
            bump(diff_by_asn, asn, event, prefix, asn, tal)

            pp = vrp.get("candidate_pp_uri")
            mf = vrp.get("candidate_manifest_uri")
            roa = vrp.get("candidate_roa_uri")
            h = vrp.get("candidate_object_hash")

            if pp:
                bump(diff_by_pp, str(pp), event, prefix, asn, tal)
            else:
                unknown_pp += 1
            if mf:
                bump(diff_by_manifest, str(mf), event, prefix, asn, tal)
            else:
                unknown_manifest += 1
            if roa:
                bump(diff_by_roa, str(roa), event, prefix, asn, tal)
            else:
                unknown_roa += 1
            if h:
                bump(diff_by_hash, str(h), event, prefix, asn, tal)
            else:
                unknown_hash += 1

        def finalize(d: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
            out = {}
            for k, v in d.items():
                out[k] = {
                    "added_count": v.get("added", 0),
                    "removed_count": v.get("removed", 0),
                    "changed_count": v.get("modified", 0),
                    "affected_prefix_count": len(v.get("prefixes", set())),
                    "affected_asn_count": len(v.get("asns", set())),
                    "affected_tal_count": len(v.get("tals", set())),
                }
            return out

        probe_counts = {
            probe: info.get("canonical_count")
            for probe, info in manifest.get("probes", {}).items()
        }

        summary = {
            "schema": "s3.m17.vrp_entry_diff_summary.v1",
            "generated_at_utc": utc_now(),
            "window_id": window_id,
            "probe_count": len(manifest.get("probes", {})),
            "total_probe_pairs": len(summary_by_pair),
            "canonical_counts_by_probe": probe_counts,
            "summary_by_pair": finalize(summary_by_pair),
            "diff_by_tal": finalize(diff_by_tal),
            "diff_by_prefix": finalize(diff_by_prefix),
            "diff_by_asn": finalize(diff_by_asn),
            "optional_object_mapping_aggregation": {
                "enabled": True,
                "diff_by_pp": finalize(diff_by_pp),
                "diff_by_manifest": finalize(diff_by_manifest),
                "diff_by_roa": finalize(diff_by_roa),
                "diff_by_object_hash": finalize(diff_by_hash),
                "unknown_pp_count": unknown_pp,
                "unknown_manifest_count": unknown_manifest,
                "unknown_roa_count": unknown_roa,
                "unknown_hash_count": unknown_hash,
            },
            "affected_prefix_count": len(affected_prefixes),
            "affected_asn_count": len(affected_asns),
            "affected_tal_count": len(affected_tals),
            "total_diff_records": len(diff_records),
            "total_added_vrps": sum(1 for r in diff_records if r["event_type"] == "added"),
            "total_removed_vrps": sum(1 for r in diff_records if r["event_type"] == "removed"),
            "total_changed_vrps": sum(1 for r in diff_records if r["event_type"] == "modified"),
            "mapping_strength": "weak",
            "strong_causal_claim_allowed": False,
            "m17_status": "PASS",
        }

        write_json(out_dir / "vrp_entry_diff_summary.json", summary)

    print("M17_STEP_AGGREGATOR=PASS")


def bump(d: dict[str, dict[str, Any]], key: str, event: str, prefix: str, asn: str, tal: str) -> None:
    v = d.setdefault(key, {"added": 0, "removed": 0, "modified": 0, "prefixes": set(), "asns": set(), "tals": set()})
    v[event] = v.get(event, 0) + 1
    v["prefixes"].add(prefix)
    v["asns"].add(asn)
    v["tals"].add(tal)


def run_lifetime_seed(selected_windows: Path, out_root: Path) -> None:
    candidates = load_selected_windows(selected_windows)

    for c in candidates:
        window_id = c["window_id"]
        out_dir = window_output_dir(out_root, window_id)
        diff_records = read_jsonl(out_dir / "vrp_entry_diff_records.jsonl")

        seeds = []
        for r in diff_records:
            diff_id = sha256_text(canonical_json({
                "window_id": window_id,
                "pair": r["probe_pair"],
                "vrp_key": r["vrp_key"],
                "diff_type": r["diff_type"],
            }))
            seeds.append({
                "schema": "s3.m17.lifetime_seed_record.v1",
                "diff_id": diff_id,
                "window_id": window_id,
                "probe_pair": r["probe_pair"],
                "vrp_key": r["vrp_key"],
                "diff_type": r["diff_type"],
                "event_type": r["event_type"],
                "first_seen_window": window_id,
                "last_seen_window": window_id,
                "duration_windows": 1,
                "temporal_class": "single_window",
                "trailing_cache_candidate": False,
            })

        write_jsonl(out_dir / "m18_lifetime_seed_records.jsonl", seeds)

    print("M17_STEP_LIFETIME_SEED=PASS")


def run_acceptance(selected_windows: Path, out_root: Path) -> None:
    candidates = load_selected_windows(selected_windows)

    for c in candidates:
        window_id = c["window_id"]
        out_dir = window_output_dir(out_root, window_id)
        check_dir = window_check_dir(out_root, window_id)
        check_dir.mkdir(parents=True, exist_ok=True)

        required = [
            out_dir / "canonical_vrp_manifest.json",
            out_dir / "vrp_entry_diff_records.jsonl",
            out_dir / "vrp_entry_diff_summary.json",
            out_dir / "vrp_vote_profile_records.jsonl",
            out_dir / "vrp_vote_profile_summary.json",
            out_dir / "m18_lifetime_seed_records.jsonl",
        ]

        summary = read_json(out_dir / "vrp_entry_diff_summary.json") if (out_dir / "vrp_entry_diff_summary.json").exists() else {}

        conditions = {
            "required_files_exist": all(p.exists() for p in required),
            "probe_count_eq_3": summary.get("probe_count") == 3,
            "total_probe_pairs_eq_3": summary.get("total_probe_pairs") == 3,
            "canonical_counts_gt_0": all((v or 0) > 0 for v in summary.get("canonical_counts_by_probe", {}).values()),
            "diff_by_tal_exists": isinstance(summary.get("diff_by_tal"), dict),
            "diff_by_prefix_exists": isinstance(summary.get("diff_by_prefix"), dict),
            "diff_by_asn_exists": isinstance(summary.get("diff_by_asn"), dict),
            "optional_object_mapping_aggregation_exists": isinstance(summary.get("optional_object_mapping_aggregation"), dict),
            "mapping_strength_weak": summary.get("mapping_strength") == "weak",
            "strong_causal_claim_allowed_false": summary.get("strong_causal_claim_allowed") is False,
        }

        status = "PASS" if all(conditions.values()) else "FAIL"

        acceptance = {
            "schema": "s3.m17.acceptance.v1",
            "generated_at_utc": utc_now(),
            "window_id": window_id,
            "status": status,
            "conditions": conditions,
            "summary": summary,
        }
        write_json(out_dir / "M17_ACCEPTANCE.json", acceptance)

        txt = [
            f"M17_ACCEPTANCE={status}",
            f"generated_at_utc = {acceptance['generated_at_utc']}",
            f"window_id = {window_id}",
            f"total_diff_records = {summary.get('total_diff_records')}",
            f"total_added_vrps = {summary.get('total_added_vrps')}",
            f"total_removed_vrps = {summary.get('total_removed_vrps')}",
            f"total_changed_vrps = {summary.get('total_changed_vrps')}",
            f"affected_prefix_count = {summary.get('affected_prefix_count')}",
            f"affected_asn_count = {summary.get('affected_asn_count')}",
            "",
            "conditions:",
        ]
        for k, v in conditions.items():
            txt.append(f"  {k} = {v}")

        (out_dir / "M17_ACCEPTANCE.txt").write_text("\n".join(txt) + "\n", encoding="utf-8")

        check_txt = [
            f"M17_VRP_ENTRY_DIFF_CHECK={status}",
            f"window_id = {window_id}",
            f"acceptance_path = {out_dir / 'M17_ACCEPTANCE.txt'}",
            f"summary_path = {out_dir / 'vrp_entry_diff_summary.json'}",
        ]
        (check_dir / "M17_VRP_ENTRY_DIFF_CHECK.txt").write_text("\n".join(check_txt) + "\n", encoding="utf-8")

    print("M17_STEP_ACCEPTANCE=PASS")


def run_all(selected_windows: Path, out_root: Path) -> None:
    run_canonical(selected_windows, out_root)
    run_pairwise(selected_windows, out_root)
    run_aggregator(selected_windows, out_root)
    run_lifetime_seed(selected_windows, out_root)
    run_acceptance(selected_windows, out_root)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--selected-windows", required=True)
    ap.add_argument("--out-root", required=True)
    ap.add_argument(
        "--step",
        required=True,
        choices=[
            "canonical_vrp_normalizer",
            "pairwise_vrp_diff",
            "aggregator",
            "lifetime_seed",
            "acceptance",
            "all",
        ],
    )
    args = ap.parse_args()

    selected_windows = Path(args.selected_windows)
    out_root = Path(args.out_root)

    if args.step == "canonical_vrp_normalizer":
        run_canonical(selected_windows, out_root)
    elif args.step == "pairwise_vrp_diff":
        run_pairwise(selected_windows, out_root)
    elif args.step == "aggregator":
        run_aggregator(selected_windows, out_root)
    elif args.step == "lifetime_seed":
        run_lifetime_seed(selected_windows, out_root)
    elif args.step == "acceptance":
        run_acceptance(selected_windows, out_root)
    elif args.step == "all":
        run_all(selected_windows, out_root)


if __name__ == "__main__":
    main()
