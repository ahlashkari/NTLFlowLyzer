#!/usr/bin/env python3

from ..network_flow_capturer import Flow
from .feature import Feature
from . import utils


class SubflowFwdPackets(Feature):
    name = "subflow_fwd_packets"
    def extract(self, flow: Flow) -> float:
        if flow.get_subflow_count() <= 0:
            return 0
        else:
            return len(flow.get_forwardpackets()) / flow.get_subflow_count()


class SubflowBwdPackets(Feature):
    name = "subflow_bwd_packets"
    def extract(self, flow: Flow) -> float:
        if flow.get_subflow_count() <= 0:
            return 0
        return len(flow.get_backwardpackets()) / flow.get_subflow_count()



class SubflowFwdBytes(Feature):
    name = "subflow_fwd_bytes"
    def extract(self, flow: Flow) -> float:
        if flow.get_subflow_count() <= 0:
            return 0
        else:
            return utils.calculate_fwd_flow_payload_bytes(flow) / flow.get_subflow_count()


class SubflowBwdBytes(Feature):
    name = "subflow_bwd_bytes"
    def extract(self, flow: Flow) -> float:
        if flow.get_subflow_count() <= 0:
            return 0
        return utils.calculate_fwd_flow_payload_bytes(flow) / flow.get_subflow_count()

