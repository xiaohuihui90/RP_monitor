import glob
import os

def load_bgp():

    files = glob.glob("data/bgp/**/rib.*", recursive=True)

    events = []

    for f in files:

        try:
            ts = os.path.getmtime(f)

            with open(f, errors="ignore") as fp:

                for line in fp:

                    # RouteViews RIB typical format filtering
                    if not line or line.startswith("#"):
                        continue

                    parts = line.strip().split()

                    # ❗关键修复：必须保证有 prefix + origin ASN
                    if len(parts) < 5:
                        continue

                    prefix = parts[0]

                    # origin ASN 通常在 AS_PATH 最后一个
                    asn = parts[-1]

                    if asn.startswith("{") or asn == "":
                        continue

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
