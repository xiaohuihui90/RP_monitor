import csv
from collections import defaultdict

def load_classification(path):
    data = defaultdict(dict)

    with open(path) as f:
        reader = csv.DictReader(f)

        for row in reader:
            key = (row["prefix"], row["asn"])

            data[key] = {
                "cd": row.get("status_cd"),
                "bj": row.get("status_bj"),
                "sg": row.get("status_sg")
            }

    return data


def to_control_plane_signal(classification):
    """
    将三probe VRP分类结果 → control-plane impact信号
    """

    signals = {}

    for k, v in classification.items():

        cd = v.get("cd")
        bj = v.get("bj")
        sg = v.get("sg")

        # ===== control-plane proxy rules =====

        # 规则1：三probe不一致 → 潜在ROV影响
        inconsistency = len(set([cd, bj, sg])) > 1

        # 规则2：Invalid传播 → 高风险
        invalid_spread = (
            cd == "Invalid" or
            bj == "Invalid" or
            sg == "Invalid"
        )

        # 最终impact score
        impact_score = 0
        if inconsistency:
            impact_score += 1
        if invalid_spread:
            impact_score += 2

        signals[k] = {
            "cd": cd,
            "bj": bj,
            "sg": sg,
            "impact_score": impact_score,
            "impact": impact_score >= 2
        }

    return signals
