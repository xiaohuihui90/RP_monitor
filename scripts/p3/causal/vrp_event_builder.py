import json
import glob
import gzip

def load_vrp_events():

    files = glob.glob("data/probe/**/vrps.raw.json*", recursive=True)

    events = []

    for f in files:

        try:
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
                    "file": f,
                    "vrp_valid": True
                })

        except:
            continue

    return events


if __name__ == "__main__":
    e = load_vrp_events()
    print("VRP_EVENTS =", len(e))
