#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path


def utc_now():
    return datetime.now(timezone.utc)


def read_csv(path: Path):
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def parse_time_from_name(name: str):
    # supports m23b_f_hourly_census_YYYYMMDDTHHMMSSZ / m23b_d_capture_YYYYMMDDTHHMMSSZ
    try:
        ts = name.rsplit("_", 1)[-1]
        return datetime.strptime(ts, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--m23b-f-out", default=os.environ.get("M23B_F_OUT", ""))
    ap.add_argument("--m23b-d-out", default=os.environ.get("M23B_D_OUT", ""))
    args = ap.parse_args()

    f_out = Path(args.m23b_f_out)
    d_out = Path(args.m23b_d_out)
    checks = f_out / "checks"
    checks.mkdir(parents=True, exist_ok=True)

    now = utc_now()
    since_24h = now - timedelta(hours=24)

    hourly_dirs = [p for p in (f_out / "hourly_census").glob("m23b_f_hourly_census_*") if p.is_dir()]
    high_dirs = [p for p in (f_out / "high_impact_capture").glob("m23b_d_capture_*") if p.is_dir()]
    daily_dirs = [p for p in (f_out / "daily_summary").glob("*") if p.is_dir()]

    hourly_recent = []
    for p in hourly_dirs:
        t = parse_time_from_name(p.name)
        if t and t >= since_24h:
            hourly_recent.append(p)

    high_recent = []
    for p in high_dirs:
        t = parse_time_from_name(p.name)
        if t and t >= since_24h:
            high_recent.append(p)

    latest_hourly_age = None
    if hourly_dirs:
        latest = max((parse_time_from_name(p.name), p) for p in hourly_dirs if parse_time_from_name(p.name))[0]
        latest_hourly_age = round((now - latest).total_seconds() / 60, 2)

    latest_high_age = None
    if high_dirs:
        latest = max((parse_time_from_name(p.name), p) for p in high_dirs if parse_time_from_name(p.name))[0]
        latest_high_age = round((now - latest).total_seconds() / 60, 2)

    latest_daily_age = None
    if daily_dirs:
        latest_day = sorted(daily_dirs)[-1]
        try:
            dt = datetime.fromisoformat(latest_day.name).replace(tzinfo=timezone.utc)
            latest_daily_age = round((now - dt).total_seconds() / 3600, 2)
        except Exception:
            latest_daily_age = None

    # Output status thresholds
    pass_cond = True
    warnings = []

    if latest_hourly_age is None or latest_hourly_age > 90:
        pass_cond = False
        warnings.append("hourly_census_stale_or_missing")
    if latest_high_age is None or latest_high_age > 60:
        pass_cond = False
        warnings.append("high_impact_capture_stale_or_missing")
    if not daily_dirs:
        warnings.append("daily_summary_missing")

    records_csv = d_out / "m23b_d_same_window_capture_records.csv"
    high_records = read_csv(records_csv)

    status = "PASS" if pass_cond else "WARNING"

    check = "\n".join([
        f"M23B_F_SCHEDULER_HEALTH={status}",
        f"checked_at_utc = {now.replace(microsecond=0).isoformat().replace('+00:00','Z')}",
        f"hourly_census_total = {len(hourly_dirs)}",
        f"hourly_census_recent_24h = {len(hourly_recent)}",
        f"high_impact_capture_total = {len(high_dirs)}",
        f"high_impact_capture_recent_24h = {len(high_recent)}",
        f"latest_hourly_age_minutes = {latest_hourly_age}",
        f"latest_high_impact_age_minutes = {latest_high_age}",
        f"daily_summary_total = {len(daily_dirs)}",
        f"latest_daily_age_hours = {latest_daily_age}",
        f"high_impact_global_record_count = {len(high_records)}",
        f"warnings = {warnings}",
        "semantic_boundary = scheduler_health_check_not_measurement",
        "",
    ])

    (checks / "M23B_F_SCHEDULER_HEALTH_CHECK.txt").write_text(check, encoding="utf-8")
    print(check)


if __name__ == "__main__":
    main()
