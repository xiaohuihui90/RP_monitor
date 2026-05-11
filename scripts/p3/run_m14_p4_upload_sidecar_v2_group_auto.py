#!/usr/bin/env python3
from __future__ import annotations

import argparse
import cgi
import gzip
import hashlib
import json
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

REQUIRED_PROBES = ["probe-cd", "probe-bj", "probe-sg"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_name(s: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in s)


def parse_time(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def compact_time_for_group(s: str | None) -> str:
    dt = parse_time(s)
    if not dt:
        return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return dt.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def gzip_valid(path: Path) -> bool:
    try:
        with gzip.open(path, "rb") as f:
            while f.read(1024 * 1024):
                pass
        return True
    except Exception:
        return False


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def parse_expected_sha256(sha_path: Path, target_name: str) -> str | None:
    if not sha_path.exists():
        return None
    for line in sha_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and Path(parts[-1]).name == target_name:
            return parts[0].lower()
    return None


def load_or_init_group(path: Path, group_id: str, validator: str) -> dict[str, Any]:
    if path.exists():
        return read_json(path)
    return {
        "schema": "s3.stage3.m14.snapshot_group.v1",
        "snapshot_group_id": group_id,
        "validator": validator,
        "group_window_seconds": 300,
        "max_generated_time_skew_seconds": 600,
        "required_probes": REQUIRED_PROBES,
        "received_probes": [],
        "complete": False,
        "generated_time_min": None,
        "generated_time_max": None,
        "generated_time_skew_seconds": None,
        "m14_run_id": None,
        "created_at_utc": utc_now(),
        "updated_at_utc": utc_now(),
        "snapshots": {},
    }


def update_group(root: Path, group_id: str, probe_id: str, record: dict[str, Any]) -> dict[str, Any]:
    group_dir = root / "groups" / safe_name(group_id)
    group_path = group_dir / "group_manifest.json"

    validator = record.get("validator") or "routinator"
    group = load_or_init_group(group_path, group_id, validator)

    group.setdefault("snapshots", {})
    group["snapshots"][probe_id] = record

    received = set(group.get("received_probes", []))
    received.add(probe_id)
    group["received_probes"] = sorted(received)
    group["complete"] = all(p in received for p in REQUIRED_PROBES)

    times = []
    for snap in group["snapshots"].values():
        t = parse_time(snap.get("generatedTime"))
        if t:
            times.append(t.astimezone(timezone.utc))

    if times:
        tmin = min(times)
        tmax = max(times)
        group["generated_time_min"] = tmin.isoformat()
        group["generated_time_max"] = tmax.isoformat()
        group["generated_time_skew_seconds"] = int((tmax - tmin).total_seconds())

    group["updated_at_utc"] = utc_now()
    write_json(group_path, group)
    return group


class Handler(BaseHTTPRequestHandler):
    server_version = "M14VRPUploadSidecarV2/0.2"

    def send_json(self, code: int, obj: dict[str, Any]) -> None:
        body = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/api/v1/health":
            self.send_json(200, {
                "status": "ok",
                "service": "m14_p4_upload_sidecar_v2_group_auto",
                "root": str(self.server.root),
                "time": utc_now(),
            })
            return
        self.send_json(404, {"status": "error", "error_class": "not_found"})

    def do_POST(self) -> None:
        if self.path != "/api/v1/m14/vrp/upload":
            self.send_json(404, {"status": "error", "error_class": "not_found"})
            return

        try:
            ctype, _ = cgi.parse_header(self.headers.get("Content-Type", ""))
            if ctype != "multipart/form-data":
                self.send_json(400, {"status": "error", "error_class": "invalid_content_type"})
                return

            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={
                    "REQUEST_METHOD": "POST",
                    "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                },
            )

            def val(name: str, default: str = "") -> str:
                if name not in form:
                    return default
                item = form[name]
                if isinstance(item, list):
                    item = item[0]
                value = item.value
                return value.decode("utf-8") if isinstance(value, bytes) else str(value)

            def save_file(field: str, dst: Path) -> Path | None:
                if field not in form:
                    return None
                item = form[field]
                if isinstance(item, list):
                    item = item[0]
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(item.file.read())
                return dst

            probe_id = val("probe_id")
            validator = val("validator", "routinator")
            validator_version = val("validator_version")
            generated_time = val("generatedTime")
            explicit_group_id = val("snapshot_group_id")

            if not probe_id or not generated_time:
                self.send_json(400, {
                    "status": "error",
                    "error_class": "missing_required_field",
                    "required": ["probe_id", "generatedTime"],
                })
                return

            group_id = explicit_group_id or f"group_{compact_time_for_group(generated_time)}"
            snapshot_id = f"{probe_id}_{compact_time_for_group(generated_time)}"

            group_dir = self.server.root / "groups" / safe_name(group_id)
            probe_dir = group_dir / safe_name(probe_id)
            gzip_name = f"{probe_id}_vrps.raw.json.gz"

            manifest_path = save_file("manifest", probe_dir / "manifest.json")
            gzip_path = save_file("file", probe_dir / gzip_name)
            sha_path = save_file("sha256", probe_dir / "sha256.txt")

            if not manifest_path or not gzip_path or not sha_path:
                self.send_json(400, {
                    "status": "error",
                    "error_class": "missing_upload_file",
                    "required": ["manifest", "file", "sha256"],
                })
                return

            manifest = read_json(manifest_path)
            expected = parse_expected_sha256(sha_path, gzip_path.name)
            actual = sha256_file(gzip_path)
            sha_ok = bool(expected and expected == actual)
            gz_ok = gzip_valid(gzip_path)

            record = {
                "snapshot_id": snapshot_id,
                "snapshot_group_id": group_id,
                "probe_id": probe_id,
                "validator": validator,
                "validator_version": validator_version or manifest.get("validator_version"),
                "generatedTime": generated_time,
                "export_started_at": manifest.get("export_started_at"),
                "export_finished_at": manifest.get("export_finished_at"),
                "roa_count": manifest.get("roa_count"),
                "raw_json_size_bytes": manifest.get("raw_json_size_bytes"),
                "gzip_size_bytes": gzip_path.stat().st_size if gzip_path.exists() else None,
                "sha256_gzip_expected": expected,
                "sha256_gzip_actual": actual,
                "sha256_gzip_ok": sha_ok,
                "gzip_valid": gz_ok,
                "local_path": str(gzip_path),
                "received_at_utc": utc_now(),
                "explicit_snapshot_group_id_used": bool(explicit_group_id),
            }

            if not sha_ok or not gz_ok:
                self.send_json(400, {
                    "status": "error",
                    "error_class": "integrity_check_failed",
                    "snapshot_record": record,
                })
                return

            write_json(probe_dir / "snapshot_record.json", record)
            group = update_group(self.server.root, group_id, probe_id, record)

            self.send_json(200, {
                "status": "ok",
                "snapshot_record": record,
                "group": group,
            })

        except Exception as exc:
            self.send_json(500, {
                "status": "error",
                "error_class": "internal_error",
                "message": str(exc),
            })


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=28114)
    parser.add_argument("--root", default="data/p3_collector/m14_vrp_snapshots")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    root.mkdir(parents=True, exist_ok=True)

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    httpd.root = root

    print(json.dumps({
        "status": "starting",
        "service": "m14_p4_upload_sidecar_v2_group_auto",
        "host": args.host,
        "port": args.port,
        "root": str(root),
    }, ensure_ascii=False, indent=2), flush=True)

    httpd.serve_forever()


if __name__ == "__main__":
    main()
