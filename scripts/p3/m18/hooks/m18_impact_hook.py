import json
import os

def compute_impact(record):

    cd = record.get("cd_state")
    bj = record.get("bj_state")
    sg = record.get("sg_state")

    # ===== control-plane proxy rule =====
    inconsistent = len({cd, bj, sg}) > 1
    invalid = "Invalid" in [cd, bj, sg]

    score = 0
    if inconsistent:
        score += 1
    if invalid:
        score += 2

    return {
        "impact": score >= 2,
        "score": score
    }
