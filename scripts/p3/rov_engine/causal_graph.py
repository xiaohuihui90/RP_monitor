def build_graph(vrp, rov, bgp):
    """
    NDSS级 causal graph
    """

    return {
        "VRP": vrp,
        "ROV": rov,
        "BGP": bgp,
        "edges": [
            "VRP -> ROV",
            "ROV -> BGP",
            "VRP -> BGP (indirect)"
        ]
    }
