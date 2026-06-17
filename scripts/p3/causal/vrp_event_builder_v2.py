import json
import glob
import time

def load():

    files = glob.glob("data/probe/**/vrps.raw.json*", recursive=True)

    events = []

    for f in files:

        try:
            with open(f) as fp:
                data = json.load(fp)

            ts = int(time.time())

            for r in data.get("roas", []):
                events.append({
                    "prefix": r["prefix"],
                    "asn": r["asn"].replace("AS",""),
                    "timestamp": ts
                })

        except:
            continue

    return events
