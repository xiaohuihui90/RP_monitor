#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


PROBES = ["probe-cd", "probe-bj", "probe-sg"]

DEFAULT_EXCLUDE_DIR_NAMES = {
    ".git",
    "__pycache__",
    "raw_objects",

    # M17 scanner outputs. These must never be used as scanner inputs.
    "m17_anomalies",
    "e4a_joint_m17",
}

OBJECT_ROOT_WHITELIST = {
    "object_set_root",
    "effective_object_root",
    "all_object_root",
    "semantic_object_root",

    "mft_semantic_root",
    "manifest_semantic_root",
    "manifest_filelist_root",
    "manifest_object_root",

    "roa_semantic_root",
    "roa_vrp_key_root",
    "roa_candidate_key_root",

    "cer_semantic_root",
    "cer_chain_index_root",
    "cer_resource_root",

    "crl_frozen_hash_root",
    "crl_live_semantic_root",
    "crl_revoked_set_root",
    "crl_freshness_root",
    "crl_issuer_aki_root",

    "aspa_semantic_root",
    "aspa_provider_set_root",
    "gbr_semantic_root",
    "sig_semantic_root",
    "rsc_semantic_root",
    "tak_semantic_root",
    "unknown_object_root",
    "auxiliary_object_root",
}

REPO_HOST_ROOT_BLACKLIST = {
    "com",
    "net",
    "org",
    "br",
    "ki",
    "network",
    "https",
    "http",
    "rsync",
}


def utc_now_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def should_exclude_path(path: Path, extra_exclude_dir_names: Optional[Iterable[str]] = None) -> bool:
    exclude = set(DEFAULT_EXCLUDE_DIR_NAMES)
    if extra_exclude_dir_names:
        exclude.update(extra_exclude_dir_names)

    return any(part in exclude for part in path.parts)


def iter_files(
    root: Path,
    *,
    suffixes: tuple[str, ...] = (".json", ".jsonl", ".txt"),
    include_substrings: Optional[List[str]] = None,
    include_names: Optional[List[str]] = None,
    exclude_dir_names: Optional[List[str]] = None,
    max_files: int = 500,
    max_depth: int = 8,
) -> List[Path]:
    root = Path(root)
    if not root.exists():
        return []

    include_substrings = include_substrings or []
    include_names = include_names or []
    exclude_set = set(DEFAULT_EXCLUDE_DIR_NAMES)
    if exclude_dir_names:
        exclude_set.update(exclude_dir_names)

    out: List[Path] = []
    root_depth = len(root.parts)

    for dirpath, dirnames, filenames in os.walk(root):
        pdir = Path(dirpath)

        dirnames[:] = [
            d for d in dirnames
            if d not in exclude_set and not should_exclude_path(pdir / d, exclude_set)
        ]

        if should_exclude_path(pdir, exclude_set):
            continue

        depth = len(pdir.parts) - root_depth
        if depth > max_depth:
            dirnames[:] = []
            continue

        for name in filenames:
            p = pdir / name

            if should_exclude_path(p, exclude_set):
                continue

            if suffixes and p.suffix not in suffixes:
                continue

            matched_name = name in include_names if include_names else False
            s = str(p)
            matched_sub = any(x in s for x in include_substrings) if include_substrings else False

            if include_names or include_substrings:
                if not (matched_name or matched_sub):
                    continue

            out.append(p)
            if len(out) >= max_files:
                return sorted(out, key=lambda x: x.stat().st_mtime if x.exists() else 0, reverse=True)

    return sorted(out, key=lambda x: x.stat().st_mtime if x.exists() else 0, reverse=True)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path, *, max_lines: int = 20000) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= max_lines:
                break
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                rows.append(obj)
    return rows


def safe_read_json(path: Path) -> Optional[Any]:
    try:
        return read_json(path)
    except Exception:
        return None


def safe_read_jsonl(path: Path, *, max_lines: int = 20000) -> List[Dict[str, Any]]:
    try:
        return read_jsonl(path, max_lines=max_lines)
    except Exception:
        return []


def infer_probe_id_from_path(path: Path) -> Optional[str]:
    s = str(path)
    for probe in PROBES:
        if probe in s:
            return probe
    return None


def first_value(row: Dict[str, Any], keys: Iterable[str]) -> Any:
    for k in keys:
        if k in row and row[k] not in (None, ""):
            return row[k]
    return None


def normalize_status(value: Any) -> str:
    if value is None:
        return "unknown"
    s = str(value).strip().lower()
    if s in {"ok", "success", "succeeded", "200", "true"}:
        return "success"
    if s in {"fail", "failed", "error", "timeout", "false"}:
        return "failed"
    return s


def parse_dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None

    s = str(value).strip()
    if not s:
        return None

    if s.endswith("Z"):
        s2 = s[:-1] + "+00:00"
    else:
        s2 = s

    for fmt in [None, "%Y-%m-%d %H:%M:%S", "%Y%m%dT%H%M%SZ"]:
        try:
            if fmt is None:
                dt = datetime.fromisoformat(s2)
            else:
                dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            pass

    return None


def dt_to_iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def seconds_skew(values: Iterable[Any]) -> Optional[float]:
    dts = [parse_dt(v) for v in values]
    dts = [x for x in dts if x is not None]
    if len(dts) < 2:
        return None
    return (max(dts) - min(dts)).total_seconds()


def numeric_or_str(value: Any) -> Any:
    if value is None:
        return None
    s = str(value)
    if re.fullmatch(r"\d+", s):
        try:
            return int(s)
        except Exception:
            return s
    return s


def serials_nearby(values: List[Any], *, max_gap: int = 10) -> bool:
    ints = []
    for v in values:
        v2 = numeric_or_str(v)
        if not isinstance(v2, int):
            return False
        ints.append(v2)

    if len(ints) < 2:
        return False

    return max(ints) - min(ints) <= max_gap


def unique_nonempty(values: Iterable[Any]) -> List[Any]:
    out = []
    seen = set()
    for v in values:
        if v in (None, ""):
            continue
        key = json.dumps(v, ensure_ascii=False, sort_keys=True) if isinstance(v, (dict, list)) else str(v)
        if key not in seen:
            seen.add(key)
            out.append(v)
    return out


def flatten_dict(obj: Any, prefix: str = "") -> Dict[str, Any]:
    out: Dict[str, Any] = {}

    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                out.update(flatten_dict(v, p))
            elif isinstance(v, list):
                out[p] = v
            else:
                out[p] = v

    return out


def is_whitelisted_root_key(key: str) -> bool:
    k = key.split(".")[-1]
    kl = k.lower()

    if kl in REPO_HOST_ROOT_BLACKLIST:
        return False

    return kl in OBJECT_ROOT_WHITELIST


def collect_sha256_roots(obj: Any, *, whitelist_only: bool = True) -> Dict[str, str]:
    flat = flatten_dict(obj)
    roots: Dict[str, str] = {}

    for k, v in flat.items():
        short = k.split(".")[-1]
        kl = short.lower()

        if not isinstance(v, str) or not v.startswith("sha256:"):
            continue

        if whitelist_only:
            if not is_whitelisted_root_key(short):
                continue
            roots[short] = v
            continue

        if (
            kl.endswith("root")
            or kl.endswith("_root")
            or "root" in kl
            or kl in {"object_set_root", "effective_object_root"}
        ):
            if kl not in REPO_HOST_ROOT_BLACKLIST:
                roots[short] = v

    return roots


def infer_snapshot_group_from_path(path: Path) -> Optional[str]:
    s = str(path)
    m = re.search(r"(group_[A-Za-z0-9_:-]+)", s)
    if m:
        return m.group(1)
    return None


def infer_object_export_from_path(path: Path) -> Optional[str]:
    s = str(path)
    m = re.search(r"(m\d+[A-Za-z0-9_:-]*object_[0-9TZ]+|m16_b2_r2_object_[0-9TZ]+|m16_b2_object_[0-9TZ]+)", s)
    if m:
        return m.group(1)
    return None


def latest_group_dir(collector_root: Path, explicit: Optional[str] = None) -> Optional[Path]:
    if explicit:
        p = Path(explicit)
        if p.exists():
            return p

    base = collector_root / "e4a_joint_snapshots" / "groups"
    if not base.exists():
        return None

    groups = [p for p in base.iterdir() if p.is_dir()]
    if not groups:
        return None

    return sorted(groups, key=lambda p: p.stat().st_mtime, reverse=True)[0]


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=False) + "\n")
