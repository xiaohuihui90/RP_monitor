import sys
import os
sys.path.append(os.getcwd())

from scripts.p3.causal_v6.vrp_rrdp_loader import load_vrp
from scripts.p3.routeviews_ingest.parse_rib import load_bgp
from scripts.p3.causal_v6.time_align import align
from scripts.p3.causal_v6.causal import causal

def main():

    vrp = load_vrp()
    bgp = load_bgp()

    print("VRP =", len(vrp))
    print("BGP =", len(bgp))

    aligned = align(vrp, bgp)

    result = causal(aligned)

    print(result)

if __name__ == "__main__":
    main()
