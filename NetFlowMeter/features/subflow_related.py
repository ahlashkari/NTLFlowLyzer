from .feature import Feature


class SubflowFwdPackets(Feature):
    name = "subflow_fwd_packets"
    def extract(self, flow: object) -> dict:
        if flow.get_subflow_count() <= 0:
            return 0
        else:
            return len(flow.get_forwardpackets()) / flow.get_subflow_count()


class SubflowBwdPackets(Feature):
    name = "subflow_bwd_packets"
    def extract(self, flow: object) -> dict:
        if flow.get_subflow_count() <= 0:
            return 0
        return len(flow.get_backwardpackets()) / flow.get_subflow_count()



class SubflowFwdBytes(Feature):
    name = "subflow_fwd_bytes"
    def extract(self, flow: object) -> dict:
        if flow.get_subflow_count() <= 0:
            return 0
        else:
            return fwd_flow_bytes(flow) / flow.get_subflow_count()


class SubflowBwdBytes(Feature):
    name = "subflow_bwd_bytes"
    def extract(self, flow: object) -> dict:
        if flow.get_subflow_count() <= 0:
            return 0
        return bwd_flow_bytes(flow) / flow.get_subflow_count()

