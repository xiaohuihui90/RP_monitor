import json
import csv
import glob
import gzip

BASE = "data/probe"

def find_all(tag):
    # ❗关键修复：改成“文件名级匹配”
    patterns = [
        f"{BASE}/**/*{tag}_vrps.raw.json*",
        f"{BASE}/**/{tag}_vrps.raw.json*",
        f"data/p3_collector/**/*{tag}_vrps.raw.json*",
    ]

    res = []
    for p in patterns:
        res += glob.glob(p, recursive=True)

    return sorted(set(res))


def load_best(paths):
    if not paths:
        return set()

    path = paths[-1]

    if path.endswith(".gz"):
        f = gzip.open(path, "rt")
    else:
        f = open(path)

    with f:
        data = json.load(f)

    s = set()
    for r in data.get("roas", []):
        s.add((r["prefix"], r["asn"].replace("AS","")))

    return s


def classify(prefix, asn, vrp):
    return "Valid" if (prefix, str(asn)) in vrp else "Invalid"


cd_paths = find_all("probe-cd")
bj_paths = find_all("probe-bj")
sg_paths = find_all("probe-sg")

print("CD paths:", len(cd_paths))
print("BJ paths:", len(bj_paths))
print("SG paths:", len(sg_paths))

vrp_cd = load_best(cd_paths)
vrp_bj = load_best(bj_paths)
vrp_sg = load_best(sg_paths)

rows = list(vrp_cd)[:300]

out = "data/p3_control_plane_input/classification.csv"

with open(out,"w",newline="") as f:
    import csv
    w = csv.DictWriter(f, fieldnames=[
        "prefix","asn","status_cd","status_bj","status_sg"
    ])
    w.writeheader()

    for prefix,asn in rows:
        w.writerow({
            "prefix": prefix,
            "asn": asn,
            "status_cd": classify(prefix,asn,vrp_cd),
            "status_bj": classify(prefix,asn,vrp_bj),
            "status_sg": classify(prefix,asn,vrp_sg)
        })

print("DONE:", len(rows))
