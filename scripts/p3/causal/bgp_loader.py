import glob

def load_bgp():

    files = glob.glob("data/bgp/**/rib.*", recursive=True)

    bgp = {}

    for f in files[:100]:

        try:
            with open(f, errors="ignore") as fp:
                for line in fp:
                    parts = line.split()
                    if len(parts) > 1:
                        prefix = parts[0]
                        asn = parts[-1]
                        bgp[prefix] = asn
        except:
            continue

    return bgp


if __name__ == "__main__":
    b = load_bgp()
    print("BGP_ENTRIES =", len(b))
