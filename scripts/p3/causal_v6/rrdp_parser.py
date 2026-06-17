import json
import glob
import os
import re

def extract_rrdp_time(path):

    # 优先 RRDP serial / snapshot timestamp
    match = re.search(r'(\d{8}T\d{6}Z)', path)

    if match:
        return match.group(1)

    # fallback
    return str(os.path.getmtime(path))


def load_rrdp():

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
                    "time": ts,
                    "source": "vrp"
                })

        except:
            continue

    return events


if __name__ == "__main__":
    e = load_rrdp()
    print("RRDP_EVENTS =", len(e))
