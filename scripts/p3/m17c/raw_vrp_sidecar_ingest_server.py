#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", str(s))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "M17CRawVRPSidecarIngest/0.1"

    def _json(self, code: int, obj: dict[str, Any]) -> None:
        body = json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/health":
            self._json(200, {
                "status": "ok",
                "service": "m17c_raw_vrp_sidecar_ingest",
                "created_at_utc": utc_now(),
                "root": str(self.server.root_dir),
            })
            return

        self._json(404, {
            "status": "error",
            "error_class": "not_found",
            "path": self.path,
        })

    def do_POST(self) -> None:
        if self.path != "/upload":
            self._json(404, {
                "status": "error",
                "error_class": "not_found",
                "path": self.path,
            })
            return

        expected_token = os.environ.get("M245_INGEST_TOKEN", "")
        token = self.headers.get("X-M245-Token", "")

        if not expected_token or token != expected_token:
            self._json(403, {
                "status": "error",
                "error_class": "bad_token",
            })
            return

        probe_id = safe_name(self.headers.get("X-Probe-Id", ""))
        window_id = safe_name(self.headers.get("X-Window-Id", ""))
        package_name = safe_name(self.headers.get("X-Package-Name", ""))

        if not probe_id or not window_id or not package_name:
            self._json(400, {
                "status": "error",
                "error_class": "missing_required_headers",
                "required": ["X-Probe-Id", "X-Window-Id", "X-Package-Name"],
            })
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            content_length = 0

        max_bytes = int(os.environ.get("M17C_RAW_VRP_MAX_BYTES", str(1024 * 1024 * 1024)))

        if content_length <= 0:
            self._json(400, {
                "status": "error",
                "error_class": "empty_body",
            })
            return

        if content_length > max_bytes:
            self._json(413, {
                "status": "error",
                "error_class": "package_too_large",
                "content_length": content_length,
                "max_bytes": max_bytes,
            })
            return

        incoming_dir = Path(self.server.root_dir) / window_id
        incoming_dir.mkdir(parents=True, exist_ok=True)

        final_path = incoming_dir / package_name
        tmp_path = incoming_dir / (package_name + ".tmp")

        with tmp_path.open("wb") as f:
            remaining = content_length
            while remaining > 0:
                chunk = self.rfile.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                f.write(chunk)
                remaining -= len(chunk)

        if tmp_path.stat().st_size != content_length:
            tmp_path.unlink(missing_ok=True)
            self._json(400, {
                "status": "error",
                "error_class": "incomplete_upload",
                "expected_bytes": content_length,
            })
            return

        if final_path.exists():
            backup_path = incoming_dir / (package_name + f".prev_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}")
            shutil.move(str(final_path), str(backup_path))

        shutil.move(str(tmp_path), str(final_path))

        receipt = {
            "schema": "s3.m17c.raw_vrp_sidecar_upload_receipt.v1",
            "status": "received",
            "created_at_utc": utc_now(),
            "probe_id": probe_id,
            "window_id": window_id,
            "package_name": package_name,
            "package_path": str(final_path),
            "package_size_bytes": final_path.stat().st_size,
            "client_address": self.client_address[0],
        }

        receipt_path = incoming_dir / f"receipt_{probe_id}_{window_id}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
        write_json(receipt_path, receipt)

        self._json(200, receipt)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=28116)
    ap.add_argument(
        "--root-dir",
        default="data/p3_collector/m245_three_layer_baseline/raw_vrp_sidecar_incoming",
    )
    args = ap.parse_args()

    root = Path(args.root_dir)
    root.mkdir(parents=True, exist_ok=True)

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    httpd.root_dir = str(root)

    print(f"M17C_RAW_VRP_SIDECAR_INGEST_START host={args.host} port={args.port} root={root}", flush=True)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("M17C_RAW_VRP_SIDECAR_INGEST_STOP", flush=True)


if __name__ == "__main__":
    main()
