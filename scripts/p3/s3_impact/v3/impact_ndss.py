from scripts.p3.rov_engine.rov import rov_decision
from scripts.p3.rov_engine.validator import refresh_cycle
from scripts.p3.rov_engine.bgp import bgp_update
from scripts.p3.rov_engine.temporal import detect_temporal_impact
from scripts.p3.rov_engine.causal_graph import build_graph

# ===== mock input =====
vrp_state = {
    "1.0.0.0/24": "valid",
    "2.0.0.0/24": "invalid"
}

roa_match = {
    "1.0.0.0/24": True,
    "2.0.0.0/24": False
}

# ===== ROV step =====
rov_state = {}
for k in vrp_state:
    rov_state[k] = rov_decision(vrp_state[k], roa_match.get(k, False))

# ===== validator simulation =====
history = refresh_cycle(rov_state)

# ===== BGP simulation =====
bgp_result = bgp_update(history[0]["state"], history[-1]["state"])

# ===== temporal detection =====
temporal = detect_temporal_impact(history)

# ===== causal graph =====
graph = build_graph(vrp_state, rov_state, bgp_result)

print("ROV:", rov_state)
print("BGP:", bgp_result)
print("TEMPORAL IMPACT:", temporal)
print("CAUSAL GRAPH:", graph)
