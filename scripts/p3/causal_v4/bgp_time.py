import glob
import os
import re

def extract_bgp_time(path):

    # RouteViews rib.xxx.xx.xx 格式
    match = re.search(r'(\d{8}\.\d{4})', path)
    if match:
        return match.group(1)

    return str(os.path.getmtime(path))


def load_bgp():

    files = glob.glob("data/bgp/**/rib.*", recursive=True)

    events = []

    for f in files[:200]:

        try:
            ts = extract_bgp_time(f)

            with open(f, errors="ignore") as fp:
                for line in fp:
                    parts = line.split()
                    if len(parts) > 1:
                        events.append({
                            "prefix": parts[0],
                            "asn": parts[-1],
                            "timestamp": ts
                        })

        except:
            continue

    return events
