import json
import ipaddress
from collections import defaultdict

VRP_FILES = {
    'bj': 'data/p3_vrp_bj.json',
    'cd': 'data/p3_vrp_cd.json',
    'sg': 'data/p3_vrp_sg.json'
}

CSV_PATH = 'data/p3_control_plane_input/prefix_origin_as.csv'
OUT = 'data/p3_control_plane_input/classification.csv'

def classify(prefix, asn, vrps):
    for p in vrps:
        if p["prefix"] == prefix:
            if int(asn) == int(p["asn"].replace("AS","")):
                return "Valid"
    return "Invalid"

def load(path):
    with open(path) as f:
        return json.load(f)

def main():
    vrp = {k: load(v) for k,v in VRP_FILES.items()}

    import csv
    rows = []

    with open(CSV_PATH) as f:
        for line in f:
            if "," not in line:
                continue
            prefix, asn = line.strip().split(",")[:2]

            rows.append({
                "prefix": prefix,
                "asn": asn,
                "status_cd": classify(prefix, asn, vrp['cd']),
                "status_bj": classify(prefix, asn, vrp['bj']),
                "status_sg": classify(prefix, asn, vrp['sg'])
            })

    with open(OUT,"w",newline="") as f:
        import csv
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)

    print("classification done:", len(rows))

if __name__ == "__main__":
    main()
