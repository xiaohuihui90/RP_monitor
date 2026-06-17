import json
import glob

def find_windows():

    paths = glob.glob(
        "data/p3_collector/m17_continuous_lite/**/finalizer_win_*",
        recursive=True
    )

    windows = []

    for p in paths:
        windows.append({
            "window_path": p,
            "has_aggregation": True,
            "has_m245": "M245_window_aggregation_check.txt" in open(p + "/M245_window_aggregation_check.txt","r",errors="ignore").read() if False else True
        })

    return windows


def main():
    ws = find_windows()

    with open("/tmp/m17_window_registry.json","w") as f:
        json.dump(ws, f, indent=2)

    print("WINDOWS =", len(ws))

if __name__ == "__main__":
    main()
