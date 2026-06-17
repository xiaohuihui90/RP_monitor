import glob
import time

def load():

    files = glob.glob("data/bgp/**/rib.*", recursive=True)

    bgp = []

    for f in files[:200]:

        try:
            with open(f, errors="ignore") as fp:
                ts = int(time.time())

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
