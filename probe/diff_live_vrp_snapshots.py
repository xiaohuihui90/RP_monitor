#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO


SCHEMA_EVENT = "s3.probe.live_vrp_diff_event.v1"
SCHEMA_SUMMARY = "s3.probe.live_vrp_diff_summary.v2"
EVENT_ADDED = "VRP_ADDED"
EVENT_REMOVED = "VRP_REMOVED"
EVENT_CHANGED = "VRP_CHANGED"
PROGRESS_EVERY = 100_000

VOLATILE_TOP_LEVEL_FIELDS = {
    "snapshot_id",
    "probe_id",
    "vrp_key",
    "window_id",
    "diff_id",
    "capture_time_utc",
    "created_at_utc",
    "generated_at_utc",
    "updated_at_utc",
    "raw_index",
    "raw_record_index",
}


@dataclass(frozen=True, slots=True)
class VrpKey:
    tal: str
    asn: int | str
    prefix: str
    max_length: int

    def as_string(self) -> str:
        return f"{self.tal}|{self.asn}|{self.prefix}|{self.max_length}"


@dataclass(frozen=True, slots=True)
class CompactRecord:
    source_uri: str | None
    raw_record_sha256: str | None
    record_hash: str


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def progress(stage: str, line_no: int) -> None:
    if line_no > 0 and line_no % PROGRESS_EVERY == 0:
        print(f"[{utc_now()}] {stage}: read {line_no} lines", file=sys.stderr, flush=True)


def sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def stable_id(prefix: str, obj: Any, length: int = 32) -> str:
    payload = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return f"{prefix}_" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:length]


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


def atomic_write_json(path: Path, obj: Any) -> None:
    atomic_write_bytes(
        path,
        (json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )


def publish_existing_atomically(tmp_path: Path, final_path: Path) -> None:
    final_path.parent.mkdir(parents=True, exist_ok=True)
    with tmp_path.open("rb+") as f:
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, final_path)
    fsync_parent(final_path)


def read_jsonl(path: Path, stage: str):
    with path.open("r", encoding="utf-8-sig", errors="strict") as f:
        for line_no, line in enumerate(f, 1):
            progress(stage, line_no)
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at {path}:{line_no}: {exc}") from exc
            if not isinstance(obj, dict):
                raise ValueError(f"JSONL record is not an object at {path}:{line_no}")
            yield line_no, obj


def get_first(record: dict[str, Any], keys: list[str]) -> Any:
    for key in keys:
        value = record.get(key)
        if value is not None and value != "":
            return value
    return None


def parse_asn(value: Any) -> int | str | None:
    if value is None or value == "":
        return None
    text = str(value).strip()
    if text.upper().startswith("AS"):
        text = text[2:]
    try:
        return int(text)
    except ValueError:
        return text


def parse_asn_text(value: str) -> int | str:
    try:
        return int(value)
    except ValueError:
        return value


def normalize_prefix(value: Any) -> str | None:
    if value is None or value == "":
        return None
    text = str(value).strip()
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        return text


def parse_max_length(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def make_vrp_key(record: dict[str, Any], path: Path, line_no: int) -> VrpKey:
    tal_raw = get_first(record, ["tal", "ta", "trust_anchor", "trustAnchor"])
    asn_raw = get_first(record, ["asn", "asID", "as_id", "origin_asn", "originAS", "origin", "origin_as"])
    prefix_raw = get_first(record, ["prefix", "ipPrefix", "ip_prefix", "vrp_prefix"])
    max_length_raw = get_first(record, ["max_length", "maxLength", "maxlength", "maxLen", "max_len"])

    tal = str(tal_raw).strip().lower() if tal_raw is not None and str(tal_raw).strip() else None
    asn = parse_asn(asn_raw)
    prefix = normalize_prefix(prefix_raw)
    max_length = parse_max_length(max_length_raw)

    missing = []
    if tal is None:
        missing.append("tal")
    if asn is None:
        missing.append("asn")
    if prefix is None:
        missing.append("prefix")
    if max_length is None:
        missing.append("max_length")
    if missing:
        raise ValueError(f"missing or invalid VRP key fields at {path}:{line_no}: {','.join(missing)}")

    return VrpKey(tal=tal, asn=asn, prefix=prefix, max_length=max_length)


def clean_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def extract_source_uri(record: dict[str, Any]) -> str | None:
    direct = get_first(record, ["source_uri", "roa_uri", "sourceUri", "roaUri", "uri", "object_uri"])
    if direct is not None:
        return clean_string(direct)

    source_uris = record.get("source_uris")
    if isinstance(source_uris, list):
        for value in source_uris:
            text = clean_string(value)
            if text:
                return text

    raw_source = record.get("source")
    if isinstance(raw_source, str):
        return clean_string(raw_source)
    if isinstance(raw_source, dict):
        return clean_string(raw_source.get("uri") or raw_source.get("source_uri") or raw_source.get("roa_uri"))
    if isinstance(raw_source, list):
        for item in raw_source:
            if isinstance(item, dict):
                text = clean_string(item.get("uri") or item.get("source_uri") or item.get("roa_uri"))
                if text:
                    return text
    return None


def extract_raw_record_sha256(record: dict[str, Any]) -> str | None:
    direct = get_first(record, ["raw_record_sha256", "raw_record_hash", "raw_sha256"])
    if direct is not None:
        return clean_string(direct)
    raw_source = record.get("raw_source")
    if isinstance(raw_source, dict):
        nested = get_first(raw_source, ["raw_record_sha256", "raw_record_hash", "raw_sha256"])
        if nested is not None:
            return clean_string(nested)
    return None


def key_from_text(key_text: str) -> VrpKey:
    parts = key_text.split("|")
    if len(parts) != 4:
        raise ValueError(f"invalid compact VRP key: {key_text}")
    return VrpKey(tal=parts[0], asn=parse_asn_text(parts[1]), prefix=parts[2], max_length=int(parts[3]))


def compact_record_dict(key_text: str, compact: CompactRecord) -> dict[str, Any]:
    key = key_from_text(key_text)
    return {
        "tal": key.tal,
        "asn": key.asn,
        "prefix": key.prefix,
        "max_length": key.max_length,
        "source_uri": compact.source_uri,
        "vrp_key": key_text,
        "raw_record_sha256": compact.raw_record_sha256,
    }


def hash_projection(record: dict[str, Any], compact_dict: dict[str, Any]) -> dict[str, Any]:
    projection: dict[str, Any] = {"compact_record": compact_dict}
    for key, value in record.items():
        if key in VOLATILE_TOP_LEVEL_FIELDS or key == "raw_source":
            continue
        projection[key] = value
    return projection


def make_compact_record(record: dict[str, Any], path: Path, line_no: int) -> tuple[str, CompactRecord]:
    key = make_vrp_key(record, path, line_no)
    key_text = key.as_string()
    source_uri = extract_source_uri(record)
    raw_record_sha256 = extract_raw_record_sha256(record)
    compact_without_hash = {
        "tal": key.tal,
        "asn": key.asn,
        "prefix": key.prefix,
        "max_length": key.max_length,
        "source_uri": source_uri,
        "vrp_key": key_text,
        "raw_record_sha256": raw_record_sha256,
    }
    record_hash = sha256_text(json.dumps(
        hash_projection(record, compact_without_hash),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ))
    return key_text, CompactRecord(
        source_uri=source_uri,
        raw_record_sha256=raw_record_sha256,
        record_hash=record_hash,
    )


def infer_snapshot_id_from_path(path: Path) -> str:
    if path.parent.name:
        return path.parent.name
    return path.stem


def load_prev_index(path: Path) -> tuple[dict[str, CompactRecord], int, int]:
    if not path.exists():
        raise FileNotFoundError(path)
    if not path.is_file():
        raise ValueError(f"not a file: {path}")

    prev_index: dict[str, CompactRecord] = {}
    record_count = 0
    duplicate_count = 0
    for line_no, record in read_jsonl(path, "prev"):
        record_count += 1
        key_text, compact = make_compact_record(record, path, line_no)
        if key_text in prev_index:
            duplicate_count += 1
            continue
        prev_index[key_text] = compact
    print(
        f"[{utc_now()}] prev: finished lines={line_no if 'line_no' in locals() else 0} "
        f"unique_keys={len(prev_index)} duplicates={duplicate_count}",
        file=sys.stderr,
        flush=True,
    )
    return prev_index, record_count, duplicate_count


def make_diff_id(probe_id: str, prev_snapshot_id: str, curr_snapshot_id: str, prev_path: Path, curr_path: Path) -> str:
    return stable_id(
        "diff",
        {
            "probe_id": probe_id,
            "prev_snapshot_id": prev_snapshot_id,
            "curr_snapshot_id": curr_snapshot_id,
            "prev_path": str(prev_path),
            "curr_path": str(curr_path),
            "key_fields": ["tal", "asn", "prefix", "max_length"],
        },
    )


def changed_fields(prev: CompactRecord, curr: CompactRecord) -> list[str]:
    fields = []
    if prev.source_uri != curr.source_uri:
        fields.append("source_uri")
    if prev.raw_record_sha256 != curr.raw_record_sha256:
        fields.append("raw_record_sha256")
    if not fields and prev.record_hash != curr.record_hash:
        fields.append("record_hash")
    return fields


def make_event(
    event_type: str,
    probe_id: str,
    diff_id: str,
    prev_snapshot_id: str,
    curr_snapshot_id: str,
    key_text: str,
    prev: CompactRecord | None,
    curr: CompactRecord | None,
) -> dict[str, Any]:
    compact = curr or prev
    if compact is None:
        raise ValueError("event requires prev or curr compact record")
    key = key_from_text(key_text)
    event = {
        "schema": SCHEMA_EVENT,
        "event_id": stable_id("evt", {"diff_id": diff_id, "event_type": event_type, "vrp_key": key_text}),
        "event_type": event_type,
        "probe_id": probe_id,
        "diff_id": diff_id,
        "vrp_key": key_text,
        "vrp_key_fields": ["tal", "asn", "prefix", "max_length"],
        "tal": key.tal,
        "asn": key.asn,
        "prefix": key.prefix,
        "max_length": key.max_length,
        "source_uri": (curr.source_uri if curr and curr.source_uri else prev.source_uri if prev else None),
        "prev_snapshot_id": prev_snapshot_id,
        "curr_snapshot_id": curr_snapshot_id,
        "prev_record": compact_record_dict(key_text, prev) if prev else None,
        "curr_record": compact_record_dict(key_text, curr) if curr else None,
        "prev_record_hash": prev.record_hash if prev else None,
        "curr_record_hash": curr.record_hash if curr else None,
    }
    if event_type == EVENT_CHANGED and prev is not None and curr is not None:
        event["changed_fields"] = changed_fields(prev, curr)
    return event


def write_event(out_f: TextIO, event: dict[str, Any]) -> None:
    out_f.write(json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")


def open_tmp_for_events(events_path: Path) -> tuple[Path, TextIO]:
    events_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = events_path.with_name(f"{events_path.name}.tmp.{os.getpid()}.{time.time_ns()}")
    return tmp, tmp.open("w", encoding="utf-8", newline="\n")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Streaming diff two normalized live VRP snapshots.")
    parser.add_argument("--prev-normalized", required=True, help="Previous normalized_vrp.jsonl path.")
    parser.add_argument("--curr-normalized", required=True, help="Current normalized_vrp.jsonl path.")
    parser.add_argument("--probe-id", required=True, help="Probe identifier, e.g. probe-cd.")
    parser.add_argument("--out-dir", required=True, help="Directory for events.jsonl and summaries.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    started_at_utc = utc_now()
    started_monotonic = time.monotonic()

    prev_path = Path(args.prev_normalized).resolve()
    curr_path = Path(args.curr_normalized).resolve()
    out_dir = Path(args.out_dir).resolve()
    events_path = out_dir / "events.jsonl"
    summary_path = out_dir / "summary.json"
    latest_summary_path = out_dir / "latest_diff_summary.json"

    prev_snapshot_id = infer_snapshot_id_from_path(prev_path)
    curr_snapshot_id = infer_snapshot_id_from_path(curr_path)
    diff_id = make_diff_id(args.probe_id, prev_snapshot_id, curr_snapshot_id, prev_path, curr_path)

    prev_index, prev_record_count, prev_duplicate_record_count = load_prev_index(prev_path)
    seen_curr_keys: set[str] = set()
    curr_record_count = 0
    curr_duplicate_record_count = 0
    added_count = 0
    changed_count = 0
    unchanged_count = 0
    removed_count = 0

    events_tmp, out_f = open_tmp_for_events(events_path)
    try:
        with out_f:
            for line_no, record in read_jsonl(curr_path, "curr"):
                curr_record_count += 1
                key_text, curr_compact = make_compact_record(record, curr_path, line_no)
                if key_text in seen_curr_keys:
                    curr_duplicate_record_count += 1
                    continue

                seen_curr_keys.add(key_text)
                prev_compact = prev_index.get(key_text)
                if prev_compact is None:
                    write_event(
                        out_f,
                        make_event(
                            EVENT_ADDED,
                            args.probe_id,
                            diff_id,
                            prev_snapshot_id,
                            curr_snapshot_id,
                            key_text,
                            None,
                            curr_compact,
                        ),
                    )
                    added_count += 1
                elif prev_compact.record_hash != curr_compact.record_hash:
                    write_event(
                        out_f,
                        make_event(
                            EVENT_CHANGED,
                            args.probe_id,
                            diff_id,
                            prev_snapshot_id,
                            curr_snapshot_id,
                            key_text,
                            prev_compact,
                            curr_compact,
                        ),
                    )
                    changed_count += 1
                else:
                    unchanged_count += 1

            print(
                f"[{utc_now()}] curr: finished lines={line_no if 'line_no' in locals() else 0} "
                f"unique_keys={len(seen_curr_keys)} duplicates={curr_duplicate_record_count}",
                file=sys.stderr,
                flush=True,
            )

            for key_text, prev_compact in prev_index.items():
                if key_text in seen_curr_keys:
                    continue
                write_event(
                    out_f,
                    make_event(
                        EVENT_REMOVED,
                        args.probe_id,
                        diff_id,
                        prev_snapshot_id,
                        curr_snapshot_id,
                        key_text,
                        prev_compact,
                        None,
                    ),
                )
                removed_count += 1

            out_f.flush()
            os.fsync(out_f.fileno())
        publish_existing_atomically(events_tmp, events_path)
    except Exception:
        try:
            out_f.close()
        except Exception:
            pass
        try:
            events_tmp.unlink()
        except FileNotFoundError:
            pass
        raise

    finished_at_utc = utc_now()
    summary = {
        "schema": SCHEMA_SUMMARY,
        "probe_id": args.probe_id,
        "diff_id": diff_id,
        "prev_snapshot_id": prev_snapshot_id,
        "curr_snapshot_id": curr_snapshot_id,
        "prev_normalized": str(prev_path),
        "curr_normalized": str(curr_path),
        "key_fields": ["tal", "asn", "prefix", "max_length"],
        "optional_source_field": "source_uri",
        "source_uri_in_primary_key": False,
        "prev_count": len(prev_index),
        "curr_count": len(seen_curr_keys),
        "prev_record_count": prev_record_count,
        "curr_record_count": curr_record_count,
        "prev_duplicate_record_count": prev_duplicate_record_count,
        "curr_duplicate_record_count": curr_duplicate_record_count,
        "added_count": added_count,
        "removed_count": removed_count,
        "changed_count": changed_count,
        "unchanged_count": unchanged_count,
        "event_count": added_count + removed_count + changed_count,
        "events_file": str(events_path),
        "started_at_utc": started_at_utc,
        "finished_at_utc": finished_at_utc,
        "duration_sec": round(time.monotonic() - started_monotonic, 6),
    }
    atomic_write_json(summary_path, summary)
    atomic_write_json(latest_summary_path, summary)

    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
