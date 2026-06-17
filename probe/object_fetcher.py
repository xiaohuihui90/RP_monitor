from __future__ import annotations
import hashlib
from pathlib import Path
import requests

def fetch_snapshot_artifact(pp_id: str, session_id: str, serial: int, snapshot_ref: str, out_dir: str, timeout: int = 30) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    target = out / f"{pp_id}_{session_id}_{serial}_snapshot.xml"
    r = requests.get(snapshot_ref, timeout=timeout)
    r.raise_for_status()
    target.write_bytes(r.content)
    return {
        "pp_id": pp_id,
        "session_id": session_id,
        "serial": serial,
        "source_type": "snapshot",
        "artifact_path": str(target),
        "content_sha256": hashlib.sha256(r.content).hexdigest(),
        "fetch_status": "success",
        "error_class": "none",
        "failure_stage": "none",
        "http_status": r.status_code,
        "latency_ms": None,
    }
