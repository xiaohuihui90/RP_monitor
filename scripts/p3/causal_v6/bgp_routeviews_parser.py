import glob
import os
import gzip

def load_bgp():

    files = glob.glob("data/**/tempRibs/**", recursive=True)
    files += glob.glob("data/**/rib.*", recursive=True)

    events = []

    for f in files[:200]:

        try:
            if not os.path.isfile(f):
                continue

            # 支持 gzip
            if f.endswith(".gz"):
                fp = gzip.open(f, "rt", errors="ignore")
            else:
                fp = open(f, "r", errors="ignore")

            with fp:
                for line in fp:

                    parts = line.strip().split()

                    if len(parts) < 2:
                        continue

                    prefix = parts[0]
                    asn = parts[-1]

                    events.append({
                        "prefix": prefix,
                        "asn": asn
                    })

        except:
            continue

    return events
