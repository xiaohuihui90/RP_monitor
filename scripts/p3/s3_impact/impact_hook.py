class ImpactHook:

    def __init__(self, rov_engine):
        self.rov = rov_engine

    def evaluate(self, vrp_before, vrp_after, bgp_snapshot):

        rov_before = self.rov.evaluate(vrp_before, bgp_snapshot)
        rov_after  = self.rov.evaluate(vrp_after, bgp_snapshot)

        return {
            "rov_before": rov_before,
            "rov_after": rov_after,
            "impact": rov_before != rov_after
        }
