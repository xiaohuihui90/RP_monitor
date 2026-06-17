import glob

def load_bgp():

    files = glob.glob("data/bgp/**/rib.*", recursive=True)

    bgp = {}

    for f in files[:200]:  # 简化版本

        try:
            with open(f, errors="ignore") as fp:
                for line in fp:
                    if ">" in line:
                        parts = line.split()
                        if len(parts) > 2:
                            prefix = parts[1]
                            asn = parts[-1]
                            bgp[prefix] = asn
        except:
            continue

    return bgp


if __name__ == "__main__":
    b = load_bgp()
    print("BGP_ENTRIES =", len(b))
