import glob
import bz2
import os

def load_bgp():

    files = glob.glob("data/bgp/routeviews/ribs/**/*.bz2", recursive=True)

    events = []

    for f in files[:50]:   # 控制规模

        try:
            ts = os.path.getmtime(f)

            fp = bz2.open(f, "rt", errors="ignore")

            with fp:
                for line in fp:

                    parts = line.strip().split()

                    # RIB基础过滤
                    if len(parts) < 3:
                        continue

                    prefix = parts[0]
                    asn = parts[-1]

                    events.append({
                        "prefix": prefix,
                        "asn": asn,
                        "timestamp": ts
                    })

        except:
            continue

    return events


if __name__ == "__main__":
    b = load_bgp()
    print("BGP_EVENTS =", len(b))
