from .feature import Feature
### subflow ###
# def subflow_fpackets(flow):
class subflow_fpackets(Feature):
    name = "Subflow Fwd Packets"
    def extract(self, flow: object) -> dict:
        if flow.get_subflow_count() <= 0:
            return 0
        else:
            return len(flow.get_forwardpackets()) / flow.get_subflow_count()


# def subflow_bpackets(flow):
class subflow_bpackets(Feature):
    name = "Subflow Bwd Bytes"
    def extract(self, flow: object) -> dict:
        if flow.get_subflow_count() <= 0:
            return 0
        return len(flow.get_backwardpackets()) / flow.get_subflow_count()



# def subflow_fbytes(flow):
class subflow_fbytes(Feature):
    name = "Subflow Fwd Packets"
    def extract(self, flow: object) -> dict:
        if flow.get_subflow_count() <= 0:
            return 0
        else:
            return fwd_flow_bytes(flow) / flow.get_subflow_count()


# def subflow_bbytes(flow):
class subflow_bbytes(Feature):
    name = "Subflow Bwd Packets"
    def extract(self, flow: object) -> dict:
        if flow.get_subflow_count() <= 0:
            return 0
        return bwd_flow_bytes(flow) / flow.get_subflow_count()

