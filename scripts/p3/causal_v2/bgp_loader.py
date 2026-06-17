import glob
import os

def load_bgp():

    files = glob.glob("data/bgp/**/rib.*", recursive=True)

    bgp = []

    for f in files[:100]:

        try:
            ts = os.path.getmtime(f)

            with open(f, errors="ignore") as fp:
                for line in fp:
                    parts = line.split()
                    if len(parts) > 1:
                        bgp.append({
                            "prefix": parts[0],
                            "asn": parts[-1],
                            "timestamp": ts
                        })

        except:
            continue

    return bgp
