#!/usr/bin/env python3
from __future__ import annotations

import argparse
import cgi
import gzip
import hashlib
import json
import shutil
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


REQUIRED_PROBES = ["probe-cd", "probe-bj", "probe-sg"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_time(s: str) -> datetime:
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


def time_id(dt: datetime) -> str:
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y%m%dT%H%M%SZ")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


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


def safe_name(s: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in s)


class SnapshotStore:
    def __init__(self, root: Path, group_window_seconds: int, max_skew_seconds: int):
        self.root = root
        self.incoming = root / "incoming"
        self.groups = root / "groups"
        self.group_window_seconds = group_window_seconds
        self.max_skew_seconds = max_skew_seconds
        self.incoming.mkdir(parents=True, exist_ok=True)
        self.groups.mkdir(parents=True, exist_ok=True)

    def list_groups(self) -> list[dict[str, Any]]:
        out = []
        for p in sorted(self.groups.glob("group_*")):
            mf = p / "group_manifest.json"
            if mf.exists():
                try:
                    out.append(read_json(mf))
                except Exception:
                    pass
        return out

    def find_or_create_group(self, validator: str, generated_time: str) -> tuple[str, Path]:
        dt = parse_time(generated_time)

        for group_dir in sorted(self.groups.glob("group_*")):
            mf = group_dir / "group_manifest.json"
            if not mf.exists():
                continue
            obj = read_json(mf)
            if obj.get("validator") != validator:
                continue
            times = []
            for snap in obj.get("snapshots", {}).values():
                gt = snap.get("generatedTime")
                if gt:
                    times.append(parse_time(gt))
            if not times:
                continue
            new_times = times + [dt]
            skew = int((max(new_times) - min(new_times)).total_seconds())
            if skew <= self.max_skew_seconds:
                return obj["snapshot_group_id"], group_dir

        group_id = "group_" + time_id(dt)
        group_dir = self.groups / group_id
        group_dir.mkdir(parents=True, exist_ok=True)
        return group_id, group_dir

    def update_group_manifest(self, group_id: str, group_dir: Path, validator: str, snapshot_record: dict[str, Any]) -> dict[str, Any]:
        mf = group_dir / "group_manifest.json"
        if mf.exists():
            group = read_json(mf)
        else:
            group = {
                "schema": "s3.stage3.m14.snapshot_group.v1",
                "snapshot_group_id": group_id,
                "validator": validator,
                "group_window_seconds": self.group_window_seconds,
                "max_generated_time_skew_seconds": self.max_skew_seconds,
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

        probe_id = snapshot_record["probe_id"]
        group["snapshots"][probe_id] = snapshot_record
        group["received_probes"] = sorted(group["snapshots"].keys())

        times = [
            parse_time(s["generatedTime"])
            for s in group["snapshots"].values()
            if s.get("generatedTime")
        ]
        if times:
            tmin, tmax = min(times), max(times)
            group["generated_time_min"] = tmin.astimezone(timezone.utc).isoformat()
            group["generated_time_max"] = tmax.astimezone(timezone.utc).isoformat()
            group["generated_time_skew_seconds"] = int((tmax - tmin).total_seconds())

        group["complete"] = all(p in group["snapshots"] for p in REQUIRED_PROBES)
        group["updated_at_utc"] = utc_now()

        write_json(mf, group)
        return group

    def save_upload(self, fields: dict[str, str], file_bytes: bytes, manifest_bytes: bytes | None, sha256_bytes: bytes | None) -> dict[str, Any]:
        probe_id = fields.get("probe_id")
        validator = fields.get("validator") or "routinator"

        if not probe_id:
            raise ValueError("missing probe_id")
        if probe_id not in REQUIRED_PROBES:
            raise ValueError(f"unexpected probe_id: {probe_id}")

        if manifest_bytes:
            manifest = json.loads(manifest_bytes.decode("utf-8"))
        else:
            raise ValueError("missing manifest file")

        generated_time = fields.get("generatedTime") or manifest.get("generatedTime")
        if not generated_time:
            raise ValueError("missing generatedTime")

        validator_version = fields.get("validator_version") or manifest.get("validator_version")
        expected_gzip_sha256 = manifest.get("sha256_gzip")

        group_id, group_dir = self.find_or_create_group(validator, generated_time)

        snapshot_id = f"{safe_name(probe_id)}_{time_id(parse_time(generated_time))}"
        incoming_dir = self.incoming / snapshot_id
        probe_group_dir = group_dir / probe_id

        incoming_dir.mkdir(parents=True, exist_ok=True)
        probe_group_dir.mkdir(parents=True, exist_ok=True)

        gzip_name = f"{probe_id}_vrps.raw.json.gz"
        incoming_gzip = incoming_dir / gzip_name
        incoming_manifest = incoming_dir / "manifest.json"
        incoming_sha256 = incoming_dir / "sha256.txt"

        incoming_gzip.write_bytes(file_bytes)
        incoming_manifest.write_bytes(manifest_bytes)
        if sha256_bytes:
            incoming_sha256.write_bytes(sha256_bytes)

        actual_gzip_sha256 = sha256_file(incoming_gzip)
        valid_gzip = gzip_valid(incoming_gzip)
        sha256_ok = expected_gzip_sha256 == actual_gzip_sha256

        if not valid_gzip:
            raise ValueError("invalid gzip")
        if expected_gzip_sha256 and not sha256_ok:
            raise ValueError("sha256_gzip mismatch")

        shutil.copy2(incoming_gzip, probe_group_dir / gzip_name)
        shutil.copy2(incoming_manifest, probe_group_dir / "manifest.json")
        if incoming_sha256.exists():
            shutil.copy2(incoming_sha256, probe_group_dir / "sha256.txt")

        snapshot_record = {
            "snapshot_id": snapshot_id,
            "snapshot_group_id": group_id,
            "probe_id": probe_id,
            "validator": validator,
            "validator_version": validator_version,
            "generatedTime": generated_time,
            "export_started_at": manifest.get("export_started_at"),
            "export_finished_at": manifest.get("export_finished_at"),
            "roa_count": manifest.get("roa_count"),
            "raw_json_size_bytes": manifest.get("raw_json_size_bytes"),
            "gzip_size_bytes": manifest.get("gzip_size_bytes"),
            "sha256_gzip_expected": expected_gzip_sha256,
            "sha256_gzip_actual": actual_gzip_sha256,
            "sha256_gzip_ok": sha256_ok,
            "gzip_valid": valid_gzip,
            "local_path": str(probe_group_dir / gzip_name),
            "received_at_utc": utc_now(),
        }

        write_json(probe_group_dir / "upload_record.json", snapshot_record)
        group = self.update_group_manifest(group_id, group_dir, validator, snapshot_record)

        return {
            "status": "ok",
            "snapshot_record": snapshot_record,
            "group": group,
        }


class Handler(BaseHTTPRequestHandler):
    store: SnapshotStore

    def _send_json(self, code: int, obj: Any) -> None:
        data = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = urlparse(self.path).path

        if path == "/api/v1/health":
            self._send_json(200, {
                "status": "ok",
                "service": "m14_p4_upload_sidecar",
                "time": utc_now(),
            })
            return

        if path == "/api/v1/m14/vrp/snapshots":
            self._send_json(200, {
                "schema": "s3.stage3.m14.snapshot_group_list.v1",
                "groups": self.store.list_groups(),
            })
            return

        prefix = "/api/v1/m14/vrp/snapshots/"
        if path.startswith(prefix):
            group_id = path[len(prefix):].strip("/")
            mf = self.store.groups / group_id / "group_manifest.json"
            if not mf.exists():
                self._send_json(404, {"error": "group_not_found", "group_id": group_id})
                return
            self._send_json(200, read_json(mf))
            return

        if path == "/api/v1/m14/vrp/runs":
            self._send_json(200, {
                "schema": "s3.stage3.m14.run_list.v1",
                "runs": [],
                "note": "P5 will populate auto runs.",
            })
            return

        self._send_json(404, {"error": "not_found", "path": path})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/api/v1/m14/vrp/upload":
            self._send_json(404, {"error": "not_found", "path": path})
            return

        ctype, pdict = cgi.parse_header(self.headers.get("content-type"))
        if ctype != "multipart/form-data":
            self._send_json(400, {"error": "expected multipart/form-data"})
            return

        pdict["boundary"] = bytes(pdict["boundary"], "utf-8")
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={
                "REQUEST_METHOD": "POST",
                "CONTENT_TYPE": self.headers.get("content-type"),
            },
            keep_blank_values=True,
        )

        try:
            fields: dict[str, str] = {}
            for key in ["probe_id", "validator", "validator_version", "generatedTime"]:
                if key in form and not getattr(form[key], "filename", None):
                    fields[key] = form[key].value

            if "file" not in form:
                raise ValueError("missing file")
            file_bytes = form["file"].file.read()

            manifest_bytes = None
            if "manifest" in form:
                manifest_bytes = form["manifest"].file.read()

            sha256_bytes = None
            if "sha256" in form:
                sha256_bytes = form["sha256"].file.read()

            result = self.store.save_upload(fields, file_bytes, manifest_bytes, sha256_bytes)
            self._send_json(200, result)
        except Exception as exc:
            self._send_json(400, {
                "status": "error",
                "error": str(exc),
            })


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=28114)
    ap.add_argument("--root", default="data/p3_collector/m14_vrp_snapshots")
    ap.add_argument("--group-window-seconds", type=int, default=300)
    ap.add_argument("--max-skew-seconds", type=int, default=600)
    args = ap.parse_args()

    store = SnapshotStore(
        root=Path(args.root).resolve(),
        group_window_seconds=args.group_window_seconds,
        max_skew_seconds=args.max_skew_seconds,
    )
    Handler.store = store

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(json.dumps({
        "status": "starting",
        "service": "m14_p4_upload_sidecar",
        "host": args.host,
        "port": args.port,
        "root": str(store.root),
    }, ensure_ascii=False, indent=2), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
