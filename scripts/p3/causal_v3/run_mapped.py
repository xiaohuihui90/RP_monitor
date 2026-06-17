import sys
import os

sys.path.append(os.getcwd())

from scripts.p3.causal_v3.vrp_rrdp_loader import load_vrp
from scripts.p3.causal_v3.bgp_routeviews_loader import load_bgp
from scripts.p3.time_mapping.window_bgp_mapper import align_windows_bgp
from scripts.p3.causal_v3.causal_engine import causal

def main():

    vrp = load_vrp()
    bgp = load_bgp()

    aligned_pairs = align_windows_bgp()

    print("WINDOW_BGP_ALIGNED =", len(aligned_pairs))

    # 用映射后的结构做 causal inference
    result = causal(aligned_pairs)

    print(result)

if __name__ == "__main__":
    main()
