import sys
import os

sys.path.append(os.getcwd())

from scripts.p3.causal.vrp_event_builder import load_vrp_events
from scripts.p3.causal.vrp_classifier import run as classify
from scripts.p3.causal.bgp_loader import load_bgp
from scripts.p3.causal.join_engine import join
from scripts.p3.causal.time_align import align
from scripts.p3.causal.causal_engine import causal

def main():

    vrp = load_vrp_events()
    vrp = classify(vrp)

    bgp = load_bgp()

    joined = join(vrp, bgp)
    aligned = align(joined)

    result = causal(aligned)

    print(result)


if __name__ == "__main__":
    main()
