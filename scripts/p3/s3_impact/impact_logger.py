import json
from datetime import datetime

class ImpactLogger:

    def __init__(self, path):
        self.path = path

    def log(self, record):
        record["ts"] = datetime.utcnow().isoformat()

        with open(self.path, "a") as f:
            f.write(json.dumps(record) + "\n")
