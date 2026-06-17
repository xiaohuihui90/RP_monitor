import json
import glob
import os
import re

def extract_rrdp_time(path):

    # 优先从路径中提取 RRDP serial（如果有）
    match = re.search(r'(\d{8}T\d{6}Z)', path)
    if match:
        return match.group(1)

    # fallback（最差情况）
    return str(os.path.getmtime(path))


def load_vrp():

    files = glob.glob("data/probe/**/vrps.raw.json*", recursive=True)

    events = []

    for f in files:

        try:
            with open(f) as fp:
                data = json.load(fp)

            ts = extract_rrdp_time(f)

            for r in data.get("roas", []):
                events.append({
                    "prefix": r["prefix"],
                    "asn": r["asn"].replace("AS",""),
                    "timestamp": ts
                })

        except:
            continue

    return events
