import sys
import os

sys.path.append(os.getcwd())

from scripts.p3.causal_v1._1_vrp_event_builder import load_vrp_files
from scripts.p3.causal_v1._2_vrp_classifier import run as classify_run
from scripts.p3.causal_v1._3_bgp_loader import load_bgp
from scripts.p3.causal_v1._4_vrp_bgp_join import join


def main():

    vrp = load_vrp_files()
    vrp = classify_run(vrp)

    bgp = load_bgp()

    joined = join(vrp, bgp)

    total = len(joined)
    causal = sum(1 for j in joined if j["match"])

    print("TOTAL =", total)
    print("CAUSAL_MATCH =", causal)


if __name__ == "__main__":
    main()
