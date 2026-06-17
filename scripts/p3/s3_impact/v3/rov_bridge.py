from scripts.p3.rov_engine.rov_real import rov_eval

def compute_rov_transition(record):

    vrp_valid = record.get("vrp_valid", True)
    roa_match = record.get("roa_match", True)

    before = rov_eval(vrp_valid, roa_match)
    after  = rov_eval(vrp_valid, roa_match)

    return before, after
