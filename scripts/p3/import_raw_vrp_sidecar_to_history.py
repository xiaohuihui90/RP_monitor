#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def safe_extract(tar_path: Path, dest_dir: Path) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest_dir.resolve()

    with tarfile.open(tar_path, "r:gz") as tar:
        for member in tar.getmembers():
            member_path = (dest_dir / member.name).resolve()
            if not str(member_path).startswith(str(dest_resolved)):
                raise RuntimeError(f"unsafe tar member path: {member.name}")
        tar.extractall(dest_dir)


def find_manifest_dirs(extract_dir: Path) -> list[Path]:
    manifests = sorted(extract_dir.rglob("raw_vrp_export_manifest.json"))
    return [p.parent for p in manifests]


def infer_probe_id(manifest: dict[str, Any], manifest_dir: Path) -> str:
    v = manifest.get("probe_id")
    if isinstance(v, str) and v:
        return v

    for part in manifest_dir.parts:
        if part.startswith("probe-"):
            return part

    return "unknown_probe"


def infer_window_id(manifest: dict[str, Any], manifest_dir: Path) -> str:
    v = manifest.get("window_id")
    if isinstance(v, str) and v:
        return v

    for part in manifest_dir.parts:
        if part.startswith("win_") and part.endswith("_10m"):
            return part

    return "unknown_window"


def find_raw_vrp_file(manifest_dir: Path) -> Path | None:
    candidates = []
    for pattern in ["*raw_vrp.json", "*raw_vrp.jsonext", "*raw_vrp.jsonl", "*vrps.json", "*vrp.json"]:
        candidates.extend(manifest_dir.glob(pattern))

    candidates = sorted(set(candidates))
    if not candidates:
        return None

    # Prefer largest candidate.
    return sorted(candidates, key=lambda p: p.stat().st_size if p.exists() else 0)[-1]


def import_one_manifest_dir(
    manifest_dir: Path,
    history_root: Path,
    pending_root: Path,
) -> dict[str, Any]:
    manifest_path = manifest_dir / "raw_vrp_export_manifest.json"
    manifest = read_json(manifest_path)
    if not isinstance(manifest, dict):
        return {
            "manifest_dir": str(manifest_dir),
            "status": "manifest_json_invalid",
        }

    window_id = infer_window_id(manifest, manifest_dir)
    probe_id = infer_probe_id(manifest, manifest_dir)
    raw_file = find_raw_vrp_file(manifest_dir)

    history_window_dir = history_root / f"m245_window_{window_id}"
    history_exists = history_window_dir.exists()

    if history_exists:
        dest_dir = history_window_dir / "outputs" / "raw_vrp" / probe_id
        install_status = "installed_to_history"
    else:
        dest_dir = pending_root / window_id / probe_id
        install_status = "history_missing_installed_to_pending"

    dest_dir.mkdir(parents=True, exist_ok=True)

    copied_files = []
    for p in sorted(manifest_dir.iterdir()):
        if p.is_file():
            dest = dest_dir / p.name
            shutil.copy2(p, dest)
            copied_files.append(str(dest))

    raw_dest = None
    if raw_file is not None:
        raw_dest = str(dest_dir / raw_file.name)

    return {
        "window_id": window_id,
        "probe_id": probe_id,
        "manifest_dir": str(manifest_dir),
        "history_window_dir": str(history_window_dir),
        "history_exists": history_exists,
        "dest_dir": str(dest_dir),
        "status": install_status,
        "raw_file_found": raw_file is not None,
        "raw_file_source": str(raw_file) if raw_file else None,
        "raw_file_dest": raw_dest,
        "copied_files": copied_files,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--incoming-dir", required=True)
    parser.add_argument(
        "--history-root",
        default="data/p3_collector/m245_three_layer_baseline/history",
    )
    parser.add_argument(
        "--pending-root",
        default="data/p3_collector/m245_three_layer_baseline/raw_vrp_sidecar_pending",
    )
    parser.add_argument(
        "--work-dir",
        default="data/p3_collector/m245_three_layer_baseline/raw_vrp_sidecar_import_work",
    )
    parser.add_argument(
        "--out-dir",
        default="data/p3_collector/m245_three_layer_baseline/p0_acceptance",
    )
    args = parser.parse_args()

    incoming_dir = Path(args.incoming_dir)
    history_root = Path(args.history_root)
    pending_root = Path(args.pending_root)
    work_dir = Path(args.work_dir)
    out_dir = Path(args.out_dir)

    out_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)

    tar_files = sorted(incoming_dir.glob("*raw_vrp_sidecar.tar.gz"))

    records = []
    extracted_dirs = []

    for tar_path in tar_files:
        extract_dir = work_dir / tar_path.stem.replace(".tar", "")
        if extract_dir.exists():
            shutil.rmtree(extract_dir)
        extract_dir.mkdir(parents=True, exist_ok=True)

        try:
            safe_extract(tar_path, extract_dir)
        except Exception as exc:
            records.append({
                "tar_path": str(tar_path),
                "status": "extract_failed",
                "error": str(exc),
            })
            continue

        extracted_dirs.append(str(extract_dir))

        manifest_dirs = find_manifest_dirs(extract_dir)
        if not manifest_dirs:
            records.append({
                "tar_path": str(tar_path),
                "extract_dir": str(extract_dir),
                "status": "no_manifest_found",
            })
            continue

        for manifest_dir in manifest_dirs:
            rec = import_one_manifest_dir(
                manifest_dir=manifest_dir,
                history_root=history_root,
                pending_root=pending_root,
            )
            rec["tar_path"] = str(tar_path)
            rec["extract_dir"] = str(extract_dir)
            records.append(rec)

    installed_to_history = [r for r in records if r.get("status") == "installed_to_history"]
    pending = [r for r in records if r.get("status") == "history_missing_installed_to_pending"]
    failures = [r for r in records if str(r.get("status", "")).endswith("failed") or r.get("status") in {"no_manifest_found", "manifest_json_invalid"}]

    # Build per-window aggregate manifests for installed windows.
    by_window: dict[str, list[dict[str, Any]]] = {}
    for r in installed_to_history:
        wid = r.get("window_id")
        if isinstance(wid, str):
            by_window.setdefault(wid, []).append(r)

    for window_id, recs in by_window.items():
        history_window_dir = history_root / f"m245_window_{window_id}"
        agg_path = history_window_dir / "outputs" / "raw_vrp_import_manifest.json"
        write_json(agg_path, {
            "schema": "s3.p0.raw_vrp_import_manifest.v1",
            "generated_at_utc": utc_now(),
            "window_id": window_id,
            "installed_probe_count": len(recs),
            "installed_probes": sorted({str(r.get("probe_id")) for r in recs}),
            "records": recs,
        })

    summary = {
        "schema": "s3.p0.raw_vrp_sidecar_import_summary.v1",
        "generated_at_utc": utc_now(),
        "incoming_dir": str(incoming_dir),
        "history_root": str(history_root),
        "pending_root": str(pending_root),
        "work_dir": str(work_dir),
        "tar_file_count": len(tar_files),
        "record_count": len(records),
        "installed_to_history_count": len(installed_to_history),
        "pending_count": len(pending),
        "failure_count": len(failures),
        "records": records,
        "extracted_dirs": extracted_dirs,
    }

    write_json(out_dir / "p0_raw_vrp_sidecar_import_summary.json", summary)

    status = "PASS" if installed_to_history and not failures else ("PENDING" if pending and not failures else "FAIL")

    txt = [
        f"P0_RAW_VRP_SIDECAR_IMPORT={status}",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"incoming_dir = {summary['incoming_dir']}",
        f"tar_file_count = {summary['tar_file_count']}",
        f"record_count = {summary['record_count']}",
        f"installed_to_history_count = {summary['installed_to_history_count']}",
        f"pending_count = {summary['pending_count']}",
        f"failure_count = {summary['failure_count']}",
    ]

    (out_dir / "p0_raw_vrp_sidecar_import_summary.txt").write_text("\n".join(txt) + "\n", encoding="utf-8")
    print("\n".join(txt))


if __name__ == "__main__":
    main()
