from __future__ import annotations

import argparse
import json
import os
import tarfile
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_name(s: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in str(s))


def safe_extract(tar: tarfile.TarFile, dest: Path) -> None:
    dest = dest.resolve()
    for member in tar.getmembers():
        target = (dest / member.name).resolve()
        if not str(target).startswith(str(dest)):
            raise RuntimeError(f"unsafe tar member path: {member.name}")
    tar.extractall(dest)


class M245IngestHandler(BaseHTTPRequestHandler):
    server_version = "M245Ingest/0.1"

    def _json_response(self, code: int, obj: dict) -> None:
        data = json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/health":
            self._json_response(200, {
                "status": "ok",
                "service": "m245_ingest_server",
                "created_at_utc": utc_now(),
                "inbox_dir": str(self.server.inbox_dir),
            })
            return
        self._json_response(404, {"status": "not_found", "path": path})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/upload":
            self._json_response(404, {"status": "not_found", "path": path})
            return

        expected_token = os.environ.get("M245_INGEST_TOKEN", "")
        got_token = self.headers.get("X-M245-Token", "")

        if not expected_token or got_token != expected_token:
            self._json_response(403, {"status": "forbidden", "reason": "bad_token"})
            return

        probe_id = safe_name(self.headers.get("X-Probe-Id", "unknown_probe"))
        window_id = safe_name(self.headers.get("X-Window-Id", "unknown_window"))
        package_name = safe_name(self.headers.get("X-Package-Name", "probe_result.tar.gz"))

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            content_length = 0

        max_bytes = int(os.environ.get("M245_INGEST_MAX_BYTES", str(300 * 1024 * 1024)))
        if content_length <= 0:
            self._json_response(400, {"status": "bad_request", "reason": "empty_body"})
            return
        if content_length > max_bytes:
            self._json_response(413, {
                "status": "too_large",
                "content_length": content_length,
                "max_bytes": max_bytes,
            })
            return

        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        receive_dir = self.server.inbox_dir / window_id / probe_id
        receive_dir.mkdir(parents=True, exist_ok=True)

        package_path = receive_dir / f"{ts}_{package_name}"
        extract_dir = receive_dir / f"extract_{ts}"

        body = self.rfile.read(content_length)
        package_path.write_bytes(body)

        extract_status = "not_attempted"
        extract_error = None
        try:
            extract_dir.mkdir(parents=True, exist_ok=True)
            with tarfile.open(package_path, "r:gz") as tar:
                safe_extract(tar, extract_dir)
            extract_status = "ok"
        except Exception as exc:
            extract_status = "failed"
            extract_error = str(exc)

        receipt = {
            "schema": "s3.m245.ingest.receipt.v1",
            "status": "received",
            "created_at_utc": utc_now(),
            "probe_id": probe_id,
            "window_id": window_id,
            "package_name": package_name,
            "package_path": str(package_path),
            "content_length": content_length,
            "extract_status": extract_status,
            "extract_dir": str(extract_dir),
            "extract_error": extract_error,
            "client_address": self.client_address[0],
        }

        receipt_path = receive_dir / f"receipt_{ts}.json"
        receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")

        state_path = self.server.state_dir / "received_probe_runs.jsonl"
        with state_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(receipt, ensure_ascii=False, sort_keys=True) + "\n")

        self._json_response(200, receipt)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=28145)
    ap.add_argument("--project-dir", default=".")
    args = ap.parse_args()

    project_dir = Path(args.project_dir).resolve()
    inbox_dir = project_dir / "data/p3_collector/m245_three_layer_baseline/inbox"
    state_dir = project_dir / "data/p3_collector/m245_three_layer_baseline/state"
    inbox_dir.mkdir(parents=True, exist_ok=True)
    state_dir.mkdir(parents=True, exist_ok=True)

    httpd = ThreadingHTTPServer((args.host, args.port), M245IngestHandler)
    httpd.inbox_dir = inbox_dir
    httpd.state_dir = state_dir

    print(f"M245_INGEST_SERVER_START host={args.host} port={args.port}", flush=True)
    print(f"inbox_dir={inbox_dir}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
