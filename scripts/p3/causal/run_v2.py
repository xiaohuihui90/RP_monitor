import sys
import os

sys.path.append(os.getcwd())

from scripts.p3.causal.vrp_event_builder_v2 import load as load_vrp
from scripts.p3.causal.bgp_loader_v2 import load as load_bgp
from scripts.p3.causal.time_align_v2 import align
from scripts.p3.causal.causal_engine_v2 import causal

def main():

    vrp = load_vrp()
    bgp = load_bgp()

    aligned = align(vrp, bgp)

    result = causal(aligned)

    print(result)

if __name__ == "__main__":
    main()
