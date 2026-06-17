import sys
import os
sys.path.append(os.getcwd())

from scripts.p3.causal_v2.vrp_time_loader import load_vrp
from scripts.p3.causal_v2.bgp_loader import load_bgp
from scripts.p3.causal_v2.time_align import align
from scripts.p3.causal_v2.causal_engine import causal

def main():

    vrp = load_vrp()
    bgp = load_bgp()

    aligned = align(vrp, bgp)

    result = causal(aligned)

    print(result)

if __name__ == "__main__":
    main()
