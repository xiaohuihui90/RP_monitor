from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

try:
    from .rov_validate import parse_asn, parse_network, stable_id
except ImportError:  # pragma: no cover - direct script execution fallback
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from probe.rov.rov_validate import parse_asn, parse_network, stable_id


SCHEMA_ROUTE = "s3.probe.rov.bgp_route.v1"
SCHEMA_SUMMARY = "s3.probe.rov.route_build_summary.v1"
ACCEPTANCE_FILE = "checks/P10_BGP_ROUTE_TABLE_ACCEPTANCE.txt"


def build_route_table(routes: list[dict[str, Any]]) -> dict[str, Any]:
    by_key: dict[tuple[str, int], dict[str, Any]] = {}
    collectors: dict[tuple[str, int], set[str]] = defaultdict(set)
    first_seen: dict[tuple[str, int], str] = {}
    last_seen: dict[tuple[str, int], str] = {}
    for route in routes:
        key = (str(route["route_prefix"]), int(route["origin_asn"]))
        collector = str(route.get("collector") or "")
        if collector:
            collectors[key].add(collector)
        observed = str(route.get("observed_time_utc") or "")
        if observed:
            if not first_seen.get(key) or observed < first_seen[key]:
                first_seen[key] = observed
            if not last_seen.get(key) or observed > last_seen[key]:
                last_seen[key] = observed
        if key not in by_key:
            item = dict(route)
            item["collector_set"] = []
            item["collector_count"] = 0
            by_key[key] = item
    route_table = []
    for key, item in by_key.items():
        item = dict(item)
        item["collector_set"] = sorted(collectors.get(key, set()))
        item["collector_count"] = len(item["collector_set"])
        item["first_seen_utc"] = first_seen.get(key) or item.get("observed_time_utc") or ""
        item["last_seen_utc"] = last_seen.get(key) or item.get("observed_time_utc") or ""
        route_table.append(item)
    route_table.sort(key=lambda r: (str(r["route_prefix"]), int(r["origin_asn"])))
    return {
        "routes": route_table,
        "route_count": len(route_table),
        "input_route_count": len(routes),
        "duplicate_count": len(routes) - len(route_table),
    }


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso_z(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError("timestamp is required")
    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        dt = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError(f"invalid UTC timestamp: {value}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def resolve_path(value: str, root: Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (root / path).resolve()


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


def sha256_file(path: Path) -> str:
    h = sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def open_tmp_jsonl(path: Path) -> tuple[Path, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}.{time.time_ns()}")
    return tmp, tmp.open("w", encoding="utf-8", newline="\n")


def publish_existing_atomically(tmp_path: Path, final_path: Path) -> None:
    final_path.parent.mkdir(parents=True, exist_ok=True)
    with tmp_path.open("rb+") as f:
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, final_path)
    fsync_parent(final_path)


def bgpdump_available(bgpdump_bin: str) -> bool:
    if Path(bgpdump_bin).is_file():
        return True
    return shutil.which(bgpdump_bin) is not None


def normalize_executable_path(value: str) -> str:
    path = Path(value)
    if path.is_file():
        return str(path.resolve())
    found = shutil.which(value)
    return found or value


def ordinary_asn_from_token(token: str) -> int | None:
    text = token.strip().upper()
    if not text:
        return None
    if any(ch in text for ch in "{}(),[]"):
        return None
    if text.startswith("AS"):
        text = text[2:]
    if not re.fullmatch(r"\d+", text):
        return None
    return int(text)


def extract_origin_as(as_path: str, as_set_policy: str) -> tuple[int | None, bool, str | None]:
    text = str(as_path or "").strip()
    if not text:
        return None, False, "empty_as_path"

    has_as_set = "{" in text or "}" in text
    has_confed = "(" in text or ")" in text or "[" in text or "]" in text
    if has_as_set and as_set_policy == "skip":
        return None, False, "as_set"
    if has_confed and as_set_policy == "skip":
        return None, False, "confed"

    for token in reversed(text.split()):
        asn = ordinary_asn_from_token(token)
        if asn is not None:
            return asn, bool(has_as_set or has_confed), None
    return None, bool(has_as_set or has_confed), "no_origin_asn"


def parse_bgpdump_m_line(line: str, collector: str, rib_path: Path, rib_time_utc: str, include_ipv6: bool, as_set_policy: str) -> tuple[dict[str, Any] | None, str | None]:
    parts = line.rstrip("\n").split("|")
    if len(parts) < 7:
        return None, "short_bgpdump_line"

    peer_ip = parts[3].strip()
    peer_asn = parse_asn(parts[4])
    prefix_net = parse_network(parts[5])
    as_path = parts[6].strip()
    if prefix_net is None:
        return None, "invalid_prefix"
    if prefix_net.version == 6 and not include_ipv6:
        return None, "skip_ipv6"

    origin_asn, uncertain, origin_error = extract_origin_as(as_path, as_set_policy)
    if origin_error is not None:
        return None, origin_error
    if origin_asn is None:
        return None, "no_origin_asn"

    route_key = f"{collector}|{prefix_net}|{origin_asn}"
    return {
        "schema": SCHEMA_ROUTE,
        "prefix": str(prefix_net),
        "origin_asn": origin_asn,
        "collector": collector,
        "observed_time_utc": rib_time_utc,
        "peer_asn": peer_asn,
        "peer_ip": peer_ip,
        "source_type": "rib_snapshot",
        "rib_path": str(rib_path),
        "rib_time_utc": rib_time_utc,
        "as_path": as_path,
        "as_path_uncertain": uncertain,
        "route_key": route_key,
        "route_id": stable_id("bgp_route", {"collector": collector, "prefix": str(prefix_net), "origin_asn": origin_asn, "peer_asn": peer_asn}),
    }, None


def dedupe_key_for(route: dict[str, Any], policy: str) -> tuple[Any, ...]:
    if policy == "none":
        return (route["collector"], route["prefix"], route["origin_asn"], route.get("peer_ip") or "", route.get("peer_asn") or "", route.get("as_path") or "")
    if policy == "prefix_origin":
        return (route["prefix"], route["origin_asn"])
    return (route["prefix"], route["origin_asn"], route["collector"])


def initial_summary(rib_path: Path, collector: str, rib_time_utc: str, out_dir: Path) -> dict[str, Any]:
    return {
        "schema": SCHEMA_SUMMARY,
        "rib_path": str(rib_path),
        "rib_sha256": sha256_file(rib_path) if rib_path.is_file() else "",
        "collector": collector,
        "rib_time_utc": rib_time_utc,
        "raw_route_count": 0,
        "unique_prefix_origin_count": 0,
        "ipv4_count": 0,
        "ipv6_count": 0,
        "skipped_as_set_count": 0,
        "skipped_confed_count": 0,
        "skipped_ipv6_count": 0,
        "parse_error_count": 0,
        "duplicate_count": 0,
        "as_path_uncertain_count": 0,
        "bgpdump_available": False,
        "bgpdump_exit_code": None,
        "bgpdump_stderr_tail": "",
        "started_at_utc": utc_now(),
        "finished_at_utc": "",
        "outputs": {
            "routes_jsonl": str(out_dir / "routes.jsonl"),
            "route_build_summary_json": str(out_dir / "route_build_summary.json"),
        },
    }


def write_acceptance(out_dir: Path, status: str, summary: dict[str, Any], checks: dict[str, bool]) -> None:
    lines = [
        f"P10_BGP_ROUTE_TABLE={status}",
        f"rib_path={summary.get('rib_path', '')}",
        f"collector={summary.get('collector', '')}",
        f"rib_time_utc={summary.get('rib_time_utc', '')}",
        f"raw_route_count={summary.get('raw_route_count', 0)}",
        f"unique_prefix_origin_count={summary.get('unique_prefix_origin_count', 0)}",
        f"parse_error_count={summary.get('parse_error_count', 0)}",
        f"skipped_as_set_count={summary.get('skipped_as_set_count', 0)}",
        f"routes_jsonl={summary.get('outputs', {}).get('routes_jsonl', '')}",
        f"route_build_summary_json={summary.get('outputs', {}).get('route_build_summary_json', '')}",
        "",
        "[checks]",
    ]
    lines.extend(f"{key}={str(value).lower()}" for key, value in checks.items())
    atomic_write_text(out_dir / ACCEPTANCE_FILE, "\n".join(lines) + "\n")


def empty_routes_file(out_dir: Path) -> None:
    tmp, f = open_tmp_jsonl(out_dir / "routes.jsonl")
    with f:
        pass
    publish_existing_atomically(tmp, out_dir / "routes.jsonl")


def build_routes_from_rib(
    *,
    rib_path: Path,
    collector: str,
    rib_time_utc: str,
    out_dir: Path,
    bgpdump_bin: str,
    max_routes: int | None,
    include_ipv6: bool,
    as_set_policy: str,
    dedupe_key: str,
) -> tuple[dict[str, Any], dict[str, bool], str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = initial_summary(rib_path, collector, rib_time_utc, out_dir)
    routes_path = out_dir / "routes.jsonl"
    rib_exists = rib_path.is_file()
    bgpdump_cmd = normalize_executable_path(bgpdump_bin)
    available = bgpdump_available(bgpdump_cmd)
    summary["bgpdump_available"] = available

    if not rib_exists or not available:
        empty_routes_file(out_dir)
        summary["finished_at_utc"] = utc_now()
        atomic_write_json(out_dir / "route_build_summary.json", summary)
        checks = {
            "bgpdump_available": available,
            "rib_exists": rib_exists,
            "routes_jsonl_written": routes_path.is_file(),
            "route_count_gt_zero": False,
            "summary_json_ok": (out_dir / "route_build_summary.json").is_file(),
            "acceptance_written": False,
            "no_hardcoded_paths": bgpdump_bin == "bgpdump" or Path(bgpdump_bin).is_absolute() or str(bgpdump_bin).startswith("."),
        }
        return summary, checks, "FAIL"

    seen: set[tuple[Any, ...]] = set()
    tmp_routes, route_f = open_tmp_jsonl(routes_path)
    stderr_path = out_dir / "bgpdump_stderr.txt"
    cmd = [bgpdump_cmd, "-m", str(rib_path)]
    try:
        with route_f, stderr_path.open("w", encoding="utf-8", errors="replace") as err_f:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=err_f, text=True, encoding="utf-8", errors="replace")
            assert proc.stdout is not None
            for line in proc.stdout:
                if not line.strip():
                    continue
                summary["raw_route_count"] += 1
                route, error = parse_bgpdump_m_line(line, collector, rib_path, rib_time_utc, include_ipv6, as_set_policy)
                if error == "skip_ipv6":
                    summary["skipped_ipv6_count"] += 1
                    continue
                if error == "as_set":
                    summary["skipped_as_set_count"] += 1
                    continue
                if error == "confed":
                    summary["skipped_confed_count"] += 1
                    continue
                if error is not None or route is None:
                    summary["parse_error_count"] += 1
                    continue
                key = dedupe_key_for(route, dedupe_key)
                if key in seen:
                    summary["duplicate_count"] += 1
                    continue
                seen.add(key)
                if route["as_path_uncertain"]:
                    summary["as_path_uncertain_count"] += 1
                if ":" in route["prefix"]:
                    summary["ipv6_count"] += 1
                else:
                    summary["ipv4_count"] += 1
                route_f.write(json.dumps(route, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
                summary["unique_prefix_origin_count"] += 1
                if max_routes is not None and summary["unique_prefix_origin_count"] >= max_routes:
                    proc.terminate()
                    break
            if proc.stdout:
                proc.stdout.close()
            try:
                summary["bgpdump_exit_code"] = proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
                summary["bgpdump_exit_code"] = proc.wait(timeout=30)
        publish_existing_atomically(tmp_routes, routes_path)
    except Exception:
        try:
            tmp_routes.unlink()
        except FileNotFoundError:
            pass
        raise

    if stderr_path.is_file():
        text = stderr_path.read_text(encoding="utf-8", errors="replace")
        summary["bgpdump_stderr_tail"] = text[-4000:]
    summary["finished_at_utc"] = utc_now()
    atomic_write_json(out_dir / "route_build_summary.json", summary)
    checks = {
        "bgpdump_available": available,
        "rib_exists": rib_exists,
        "routes_jsonl_written": routes_path.is_file(),
        "route_count_gt_zero": summary["unique_prefix_origin_count"] > 0,
        "summary_json_ok": (out_dir / "route_build_summary.json").is_file(),
        "acceptance_written": False,
        "no_hardcoded_paths": bgpdump_bin == "bgpdump" or Path(bgpdump_bin).is_absolute() or str(bgpdump_bin).startswith("."),
    }
    status = "PASS" if all(value for key, value in checks.items() if key != "acceptance_written") and summary["bgpdump_exit_code"] in (0, -15, 143) else "FAIL"
    return summary, checks, status


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build P10 routes.jsonl from a local RouteViews/RIPE RIS MRT RIB using bgpdump -m.")
    parser.add_argument("--rib", required=True, help="Local MRT RIB path, including .bz2 files supported by bgpdump.")
    parser.add_argument("--collector", required=True, help="Collector ID, e.g. routeviews2 or rrc00.")
    parser.add_argument("--rib-time-utc", required=True, help="RIB timestamp, e.g. 2026-01-01T00:00:00Z.")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--bgpdump-bin", default="bgpdump")
    parser.add_argument("--max-routes", type=int)
    parser.add_argument("--include-ipv6", dest="include_ipv6", action="store_true", default=True)
    parser.add_argument("--no-include-ipv6", dest="include_ipv6", action="store_false")
    parser.add_argument("--as-set-policy", choices=["skip", "mark_uncertain"], default="skip")
    parser.add_argument("--dedupe-key", choices=["prefix_origin_collector", "prefix_origin", "none"], default="prefix_origin_collector")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    root = repo_root()
    try:
        rib_time_utc = parse_iso_z(args.rib_time_utc)
    except ValueError as exc:
        parser.error(str(exc))
    rib_path = resolve_path(args.rib, root)
    out_dir = resolve_path(args.out_dir, root)
    try:
        summary, checks, status = build_routes_from_rib(
            rib_path=rib_path,
            collector=args.collector,
            rib_time_utc=rib_time_utc,
            out_dir=out_dir,
            bgpdump_bin=args.bgpdump_bin,
            max_routes=args.max_routes,
            include_ipv6=bool(args.include_ipv6),
            as_set_policy=args.as_set_policy,
            dedupe_key=args.dedupe_key,
        )
        write_acceptance(out_dir, status, summary, checks)
        checks["acceptance_written"] = (out_dir / ACCEPTANCE_FILE).is_file()
        write_acceptance(out_dir, status, summary, checks)
        return 0 if status == "PASS" else 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
