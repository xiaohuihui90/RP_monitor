import sys
sys.path.append("external/control_adapter")

from vrp_validate import validate_prefix

class ROVEngine:

    def evaluate(self, vrp_key, prefix, asn):
        """
        S3统一控制面接口
        """

        try:
            return validate_prefix(prefix, asn)
        except:
            return "ERROR"
