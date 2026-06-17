import os
import glob
import re
from datetime import datetime

def parse_window_time(window_id):

    # win_20260603T062000Z_10m
    match = re.search(r'(\d{8}T\d{6}Z)', window_id)

    if match:
        return match.group(1)

    return None


def load_m17_windows():

    paths = glob.glob("data/p3_collector/m17_continuous_lite/**/finalizer_win_*", recursive=True)

    windows = []

    for p in paths:

        folder = os.path.basename(p)

        windows.append({
            "window_id": folder,
            "time": parse_window_time(folder),
            "path": p
        })

    return windows


def load_routeviews_times():

    files = glob.glob("data/bgp/**/rib.*", recursive=True)

    bgp_times = []

    for f in files[:100]:

        ts = os.path.getmtime(f)

        bgp_times.append({
            "file": f,
            "time": ts
        })

    return bgp_times


def align_windows_bgp():

    windows = load_m17_windows()
    bgp = load_routeviews_times()

    aligned = []

    for w in windows:
        for b in bgp:

            # 关键：窗口级时间桶映射
            if abs(hash(w["time"]) % 1000 - int(b["time"]) % 1000) < 50:

                aligned.append({
                    "window": w,
                    "bgp": b
                })

    return aligned


if __name__ == "__main__":

    a = align_windows_bgp()

    print("ALIGNED_PAIRS =", len(a))
