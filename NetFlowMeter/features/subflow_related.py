
### subflow ###
def subflow_fpackets(flow):
    if flow.get_subflow_count() <= 0:
        return 0
    else:
        return len(flow.get_forwardpackets()) / flow.get_subflow_count()


def subflow_bpackets(flow):
    if flow.get_subflow_count() <= 0:
        return 0
    return len(flow.get_backwardpackets()) / flow.get_subflow_count()


def subflow_fbytes(flow):
    if flow.get_subflow_count() <= 0:
        return 0
    else:
        return fwd_flow_bytes(flow) / flow.get_subflow_count()


def subflow_bbytes(flow):
    if flow.get_subflow_count() <= 0:
        return 0
    return bwd_flow_bytes(flow) / flow.get_subflow_count()

