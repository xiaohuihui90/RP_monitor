import json
import glob
import gzip

def load_rrdp_snapshots():
    files = glob.glob("data/probe/**/vrps.raw.json*", recursive=True)

    timeline = []

    for f in sorted(files):
        timeline.append({
            "time": f.split("/")[-2],
            "file": f
        })

    return timeline


def extract_state(file):

    if file.endswith(".gz"):
        f = gzip.open(file, "rt")
    else:
        f = open(file)

    with f:
        data = json.load(f)

    return {
        "roas": len(data.get("roas", []))
    }
