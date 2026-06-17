import json
import glob

def load_vrp_files():
    files = glob.glob("data/probe/**/vrps.raw.json*", recursive=True)

    events = []

    for f in files:
        try:
            with open(f) as fp:
                data = json.load(fp)

            for r in data.get("roas", []):
                events.append({
                    "prefix": r["prefix"],
                    "asn": r["asn"].replace("AS",""),
                    "file": f
                })

        except:
            continue

    return events


if __name__ == "__main__":
    e = load_vrp_files()
    print("VRP_EVENTS =", len(e))
