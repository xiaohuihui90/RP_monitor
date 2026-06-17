from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


EXPECTED_PROBES = ["probe-bj", "probe-cd", "probe-sg"]


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def latest_receipt(probe_inbox: Path) -> Path | None:
    receipts = sorted(probe_inbox.glob("receipt_*.json"))
    return receipts[-1] if receipts else None


def find_extracted_run_dir(extract_dir: Path, probe_id: str, window_id: str) -> Path | None:
    expected_name = f"m245_probe_{probe_id}_{window_id}"

    matches = [
        p for p in extract_dir.glob(f"**/{expected_name}")
        if p.is_dir() and (p / "checks" / "M245_probe_window_check.txt").exists()
    ]
    if matches:
        return matches[-1]

    fallback = [
        p.parent.parent
        for p in extract_dir.glob("**/checks/M245_probe_window_check.txt")
        if p.is_file()
    ]
    if fallback:
        return fallback[-1]

    return None


def resolve_window(project_dir: Path, window_id: str) -> dict:
    inbox_root = project_dir / "data/p3_collector/m245_three_layer_baseline/inbox" / window_id

    probe_results = {}
    hard_fail = []

    for probe_id in EXPECTED_PROBES:
        probe_inbox = inbox_root / probe_id
        receipt_path = latest_receipt(probe_inbox)

        result = {
            "probe_id": probe_id,
            "receipt_found": False,
            "extract_status": None,
            "extract_dir": None,
            "run_dir": None,
            "check_found": False,
            "summary_found": False,
            "problems": [],
        }

        if not receipt_path:
            result["problems"].append("receipt_missing")
            hard_fail.append(f"{probe_id}:receipt_missing")
            probe_results[probe_id] = result
            continue

        receipt = read_json(receipt_path)
        result["receipt_found"] = True
        result["receipt_path"] = str(receipt_path)
        result["extract_status"] = receipt.get("extract_status")
        result["extract_dir"] = receipt.get("extract_dir")
        result["client_address"] = receipt.get("client_address")
        result["package_path"] = receipt.get("package_path")

        if receipt.get("extract_status") != "ok":
            result["problems"].append(f"extract_status_{receipt.get('extract_status')}")
            hard_fail.append(f"{probe_id}:extract_not_ok")
            probe_results[probe_id] = result
            continue

        extract_dir = Path(receipt.get("extract_dir", ""))
        run_dir = find_extracted_run_dir(extract_dir, probe_id, window_id)

        if not run_dir:
            result["problems"].append("extracted_run_dir_missing")
            hard_fail.append(f"{probe_id}:extracted_run_dir_missing")
            probe_results[probe_id] = result
            continue

        result["run_dir"] = str(run_dir)
        result["check_found"] = (run_dir / "checks" / "M245_probe_window_check.txt").exists()
        result["summary_found"] = (run_dir / "outputs" / "m245_probe_window_summary.json").exists()

        if not result["check_found"]:
            result["problems"].append("probe_check_missing")
            hard_fail.append(f"{probe_id}:probe_check_missing")

        if not result["summary_found"]:
            result["problems"].append("probe_summary_missing")
            hard_fail.append(f"{probe_id}:probe_summary_missing")

        probe_results[probe_id] = result

    ready = not hard_fail

    return {
        "schema": "s3.m245.g3.window_inbox_resolve.v1",
        "created_at_utc": utc_now(),
        "window_id": window_id,
        "inbox_root": str(inbox_root),
        "expected_probes": EXPECTED_PROBES,
        "ready_for_finalizer": ready,
        "probe_results": probe_results,
        "hard_fail": hard_fail,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-dir", default=".")
    ap.add_argument("--window-id", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    project_dir = Path(args.project_dir).resolve()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    result = resolve_window(project_dir, args.window_id)

    summary_path = out_dir / "M245_G3A_inbox_resolve_summary.json"
    check_path = out_dir / "M245_G3A_inbox_resolve_check.txt"

    summary_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    status = "PASS" if result["ready_for_finalizer"] else "FAIL"

    with check_path.open("w", encoding="utf-8") as f:
        f.write(f"M245_G3A_INBOX_RESOLVE={status}\n\n")
        f.write(f"created_at_utc = {result['created_at_utc']}\n")
        f.write(f"window_id = {result['window_id']}\n")
        f.write(f"inbox_root = {result['inbox_root']}\n")
        f.write(f"ready_for_finalizer = {result['ready_for_finalizer']}\n")
        for probe_id, pr in result["probe_results"].items():
            f.write(f"\n[{probe_id}]\n")
            f.write(f"receipt_found = {pr.get('receipt_found')}\n")
            f.write(f"extract_status = {pr.get('extract_status')}\n")
            f.write(f"run_dir = {pr.get('run_dir')}\n")
            f.write(f"check_found = {pr.get('check_found')}\n")
            f.write(f"summary_found = {pr.get('summary_found')}\n")
            f.write(f"problems = {pr.get('problems')}\n")
        f.write(f"\nhard_fail = {result['hard_fail']}\n")

    print(f"M245_G3A_CHECK={check_path}")
    print(f"M245_G3A_STATUS={status}")


if __name__ == "__main__":
    main()
