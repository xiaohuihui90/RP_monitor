import json
import glob

def build():
    paths = glob.glob(
        "data/p3_collector/m17_continuous_lite/**/finalizer_win_*",
        recursive=True
    )

    index = {}

    for p in paths:
        key = p.split("finalizer_win_")[-1].split("/")[0]
        index[key] = p

    return index


if __name__ == "__main__":
    idx = build()
    print("WINDOWS:", len(idx))
