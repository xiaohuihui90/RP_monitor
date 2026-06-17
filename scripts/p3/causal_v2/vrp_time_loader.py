import json
import glob
import gzip
import os

def load_vrp():

    files = glob.glob("data/probe/**/vrps.raw.json*", recursive=True)

    events = []

    for f in files:

        try:
            # 用文件时间作为临时时间源（后面可替换RRDP serial）
            ts = os.path.getmtime(f)

            if f.endswith(".gz"):
                fp = gzip.open(f, "rt")
            else:
                fp = open(f)

            with fp:
                data = json.load(fp)

            for r in data.get("roas", []):
                events.append({
                    "prefix": r.get("prefix"),
                    "asn": r.get("asn", "").replace("AS",""),
                    "timestamp": ts
                })

        except:
            continue

    return events


if __name__ == "__main__":
    e = load_vrp()
    print("VRP_EVENTS =", len(e))
