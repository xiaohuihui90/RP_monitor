import time

def refresh_cycle(state, interval=3600):
    """
    模拟 validator refresh（M18核心）
    """

    history = []

    for t in range(3):  # 3个周期
        snapshot = {
            "time": t * interval,
            "state": state.copy()
        }
        history.append(snapshot)

    return history
