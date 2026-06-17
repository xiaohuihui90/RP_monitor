import json
import glob
import os
import re

def extract_time_from_path(path):

    # 尝试从目录名提取时间（你M17/M18结构）
    match = re.search(r'(\d{8}T\d{6}Z)', path)
    if match:
        return match.group(1)

    # fallback
    return str(os.path.getmtime(path))


def load_vrp():

    files = glob.glob("data/probe/**/vrps.raw.json*", recursive=True)

    events = []

    for f in files:

        try:
            with open(f) as fp:
                data = json.load(fp)

            ts = extract_time_from_path(f)

            for r in data.get("roas", []):
                events.append({
                    "prefix": r["prefix"],
                    "asn": r["asn"].replace("AS",""),
                    "timestamp": ts
                })

        except:
            continue

    return events


if __name__ == "__main__":
    e = load_vrp()
    print("VRP_EVENTS =", len(e))
