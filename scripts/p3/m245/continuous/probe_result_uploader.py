from __future__ import annotations

import argparse
import json
import tarfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_name(s: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in str(s))


def add_path(tar: tarfile.TarFile, path: Path, arcname: Path) -> None:
    if not path.exists():
        return
    tar.add(path, arcname=str(arcname), recursive=True)


def make_light_package(project_dir: Path, run_dir: Path, out_dir: Path, probe_id: str, window_id: str, stdout_path: Path | None) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir.mkdir(parents=True, exist_ok=True)

    package_name = f"m245_probe_{safe_name(probe_id)}_{safe_name(window_id)}_light_{ts}.tar.gz"
    package_path = out_dir / package_name

    run_dir = run_dir.resolve()
    project_dir = project_dir.resolve()

    try:
        run_rel = run_dir.relative_to(project_dir)
    except ValueError:
        run_rel = Path("external_run_dir") / run_dir.name

    with tarfile.open(package_path, "w:gz") as tar:
        for name in ["indexes", "outputs", "checks"]:
            add_path(tar, run_dir / name, run_rel / name)

        add_path(tar, run_dir / "run_manifest.json", run_rel / "run_manifest.json")

        if stdout_path and stdout_path.exists():
            tar.add(stdout_path, arcname=f"extras/{stdout_path.name}")

    return package_path


def upload(package_path: Path, collector_url: str, token: str, probe_id: str, window_id: str) -> dict:
    data = package_path.read_bytes()
    req = urllib.request.Request(
        collector_url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/gzip",
            "Content-Length": str(len(data)),
            "X-M245-Token": token,
            "X-Probe-Id": probe_id,
            "X-Window-Id": window_id,
            "X-Package-Name": package_path.name,
        },
    )

    with urllib.request.urlopen(req, timeout=120) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        return json.loads(body)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-dir", required=True)
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--probe-id", required=True)
    ap.add_argument("--window-id", required=True)
    ap.add_argument("--collector-url", required=True)
    ap.add_argument("--token", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--stdout", default="")
    args = ap.parse_args()

    project_dir = Path(args.project_dir)
    run_dir = Path(args.run_dir)
    out_dir = Path(args.out_dir)
    stdout_path = Path(args.stdout) if args.stdout else None

    package_path = make_light_package(
        project_dir=project_dir,
        run_dir=run_dir,
        out_dir=out_dir,
        probe_id=args.probe_id,
        window_id=args.window_id,
        stdout_path=stdout_path,
    )

    receipt = upload(
        package_path=package_path,
        collector_url=args.collector_url,
        token=args.token,
        probe_id=args.probe_id,
        window_id=args.window_id,
    )

    result = {
        "schema": "s3.m245.probe_upload_result.v1",
        "status": "PASS" if receipt.get("status") == "received" else "FAIL",
        "created_at_utc": utc_now(),
        "probe_id": args.probe_id,
        "window_id": args.window_id,
        "package_path": str(package_path),
        "package_size_bytes": package_path.stat().st_size,
        "collector_url": args.collector_url,
        "receipt": receipt,
    }

    result_path = out_dir / f"upload_result_{safe_name(args.probe_id)}_{safe_name(args.window_id)}.json"
    result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")

    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
