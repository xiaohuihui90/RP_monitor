#!/usr/bin/env python3
from __future__ import annotations

import argparse
import cgi
import hashlib
import json
import tarfile
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

REQUIRED_PROBES = ["probe-cd", "probe-bj", "probe-sg"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_name(s: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in s)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def expected_sha256(sha_path: Path, target_name: str) -> str | None:
    if not sha_path.exists():
        return None

    for line in sha_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and Path(parts[-1]).name == target_name:
            return parts[0].lower()

    return None


def tar_gz_valid(path: Path) -> bool:
    try:
        with tarfile.open(path, "r:gz") as tar:
            tar.getmembers()
        return True
    except Exception:
        return False


def extract_selected(tar_path: Path, dst_dir: Path) -> list[str]:
    allowed = {
        "object_snapshot_record.json",
        "object_inventory.jsonl",
        "active_manifest_records.jsonl",
    }

    extracted = []

    with tarfile.open(tar_path, "r:gz") as tar:
        for member in tar.getmembers():
            name = Path(member.name).name
            if name not in allowed:
                continue

            src = tar.extractfile(member)
            if src is None:
                continue

            dst = dst_dir / name
            dst.write_bytes(src.read())
            extracted.append(str(dst))

    return extracted


def load_or_init_group(group_path: Path, snapshot_group_id: str) -> dict[str, Any]:
    if group_path.exists():
        return read_json(group_path)

    return {
        "schema": "s3.stage3.joint_snapshot_group.v1",
        "snapshot_group_id": snapshot_group_id,
        "required_probes": REQUIRED_PROBES,
        "received_vrp_probes": [],
        "received_object_probes": [],
        "vrp_group_complete": False,
        "object_group_complete": False,
        "joint_group_complete": False,
        "generated_time_min": None,
        "generated_time_max": None,
        "generated_time_skew_seconds": None,
        "window_mapping_level": "unknown",
        "snapshots": {},
        "created_at_utc": utc_now(),
        "updated_at_utc": utc_now(),
    }


def update_group(root: Path, snapshot_group_id: str, probe_id: str, record: dict[str, Any], object_dir: Path) -> dict[str, Any]:
    group_dir = root / "groups" / safe_name(snapshot_group_id)
    group_path = group_dir / "joint_group_manifest.json"

    group = load_or_init_group(group_path, snapshot_group_id)

    received_object = set(group.get("received_object_probes", []))
    received_object.add(probe_id)

    group["received_object_probes"] = sorted(received_object)
    group["object_group_complete"] = all(p in received_object for p in REQUIRED_PROBES)

    received_vrp = set(group.get("received_vrp_probes", []))
    group["vrp_group_complete"] = all(p in received_vrp for p in REQUIRED_PROBES) if received_vrp else False
    group["joint_group_complete"] = bool(group["vrp_group_complete"] and group["object_group_complete"])

    group.setdefault("snapshots", {})
    old = group["snapshots"].get(probe_id, {})

    old.update({
        "probe_id": probe_id,
        "snapshot_group_id": snapshot_group_id,
        "joint_snapshot_id": record.get("joint_snapshot_id"),
        "object_received": True,
        "object_snapshot_record_path": str(object_dir / "object_snapshot_record.json"),
        "object_snapshot_tar_gz_path": str(object_dir / "object_snapshot.tar.gz"),
        "object_inventory_count": record.get("object_inventory_count"),
        "active_manifest_count": record.get("active_manifest_count"),
        "object_set_root": record.get("object_set_root"),
        "effective_object_root": record.get("effective_object_root"),
        "object_source_mode": record.get("object_source_mode"),
        "object_export_started_at": record.get("object_export_started_at"),
        "object_export_finished_at": record.get("object_export_finished_at"),
        "received_at_utc": utc_now(),
    })

    group["snapshots"][probe_id] = old

    times = []
    for snap in group["snapshots"].values():
        t = snap.get("object_export_started_at")
        if not t:
            continue
        try:
            times.append(datetime.fromisoformat(t.replace("Z", "+00:00")))
        except Exception:
            pass

    if times:
        tmin = min(times)
        tmax = max(times)
        skew = int((tmax - tmin).total_seconds())
        group["generated_time_min"] = tmin.isoformat()
        group["generated_time_max"] = tmax.isoformat()
        group["generated_time_skew_seconds"] = skew

        if skew <= 300:
            group["window_mapping_level"] = "strong"
        elif skew <= 600:
            group["window_mapping_level"] = "acceptable"
        else:
            group["window_mapping_level"] = "weak"

    group["updated_at_utc"] = utc_now()
    write_json(group_path, group)
    return group


class Handler(BaseHTTPRequestHandler):
    server_version = "E4AObjectUploadSidecar/0.1"

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
                "service": "e4a_object_upload_sidecar",
                "port": self.server.server_port,
                "root": str(self.server.root),
                "time": utc_now(),
            })
            return

        self.send_json(404, {"status": "error", "error_class": "not_found"})

    def do_POST(self) -> None:
        if self.path != "/api/v1/e4a/object/upload":
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

            def get_value(name: str) -> str | None:
                if name not in form:
                    return None
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

            probe_id = get_value("probe_id")
            snapshot_group_id = get_value("snapshot_group_id")
            joint_snapshot_id = get_value("joint_snapshot_id")

            if not probe_id or not snapshot_group_id:
                self.send_json(400, {
                    "status": "error",
                    "error_class": "missing_required_field",
                    "required": ["probe_id", "snapshot_group_id"],
                })
                return

            object_dir = self.server.root / "groups" / safe_name(snapshot_group_id) / safe_name(probe_id) / "object"

            record_path = save_file("object_snapshot_record", object_dir / "object_snapshot_record.json")
            tar_path = save_file("object_snapshot_tar_gz", object_dir / "object_snapshot.tar.gz")
            sha_path = save_file("sha256", object_dir / "sha256.txt")

            if not record_path or not tar_path or not sha_path:
                self.send_json(400, {
                    "status": "error",
                    "error_class": "missing_upload_file",
                    "required": ["object_snapshot_record", "object_snapshot_tar_gz", "sha256"],
                })
                return

            record = read_json(record_path)

            if not joint_snapshot_id:
                joint_snapshot_id = record.get("joint_snapshot_id")

            expected = expected_sha256(sha_path, "object_snapshot.tar.gz")
            actual = sha256_file(tar_path)
            sha_ok = bool(expected and expected == actual)
            tar_ok = tar_gz_valid(tar_path)

            extracted = []
            if tar_ok:
                extracted = extract_selected(tar_path, object_dir)

            blockers = []
            if not sha_ok:
                blockers.append("sha256_mismatch")
            if not tar_ok:
                blockers.append("tar_invalid")
            if not record.get("object_set_root"):
                blockers.append("object_set_root_missing")
            if not record.get("effective_object_root"):
                blockers.append("effective_object_root_missing")
            if not record.get("object_inventory_count"):
                blockers.append("object_inventory_empty")

            upload_record = {
                "schema": "s3.stage3.e4a.object_upload_record.v1",
                "status": "ok" if not blockers else "blocked",
                "probe_id": probe_id,
                "snapshot_group_id": snapshot_group_id,
                "joint_snapshot_id": joint_snapshot_id,
                "received_at_utc": utc_now(),
                "object_dir": str(object_dir),
                "sha256_expected": expected,
                "sha256_actual": actual,
                "sha256_ok": sha_ok,
                "tar_valid": tar_ok,
                "extracted_files": extracted,
                "object_inventory_count": record.get("object_inventory_count"),
                "active_manifest_count": record.get("active_manifest_count"),
                "object_set_root": record.get("object_set_root"),
                "effective_object_root": record.get("effective_object_root"),
                "object_source_mode": record.get("object_source_mode"),
                "blockers": blockers,
            }

            write_json(object_dir / "object_upload_record.json", upload_record)
            group = update_group(self.server.root, snapshot_group_id, probe_id, record, object_dir)

            self.send_json(200, {
                "status": "ok" if not blockers else "blocked",
                "object_upload_record": upload_record,
                "joint_group": group,
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
    parser.add_argument("--port", type=int, default=28115)
    parser.add_argument("--root", default="data/p3_collector/e4a_joint_snapshots")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    root.mkdir(parents=True, exist_ok=True)

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    httpd.root = root

    print(json.dumps({
        "status": "starting",
        "service": "e4a_object_upload_sidecar",
        "host": args.host,
        "port": args.port,
        "root": str(root),
    }, ensure_ascii=False, indent=2), flush=True)

    httpd.serve_forever()


if __name__ == "__main__":
    main()
