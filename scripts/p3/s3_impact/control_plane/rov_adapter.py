# ===== S3 CONTROL PLANE ADAPTER =====

class ROVEngine:

    def __init__(self):
        pass

    def evaluate(self, vrp_set, bgp_route):
        """
        简化版ROV逻辑（先保证可运行）
        后续再替换成你同事真实代码
        """

        if vrp_set is None:
            return "NOTFOUND"

        # mock logic（可替换真实 validator）
        if isinstance(vrp_set, str) and "invalid" in vrp_set:
            return "INVALID"

        return "VALID"
