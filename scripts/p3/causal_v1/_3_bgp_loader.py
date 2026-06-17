import glob

def load_bgp():

    files = glob.glob("data/bgp/**/rib.*", recursive=True)

    bgp = {}

    for f in files[:50]:

        try:
            with open(f, errors="ignore") as fp:
                for line in fp:
                    if len(line.split()) > 1:
                        parts = line.split()
                        prefix = parts[0]
                        asn = parts[-1]
                        bgp[prefix] = asn
        except:
            continue

    return bgp
