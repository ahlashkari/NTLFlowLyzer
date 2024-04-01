#!/usr/bin/env python3

from ..network_flow_capturer import Flow
from .feature import Feature


class PacketsCount(Feature):
    name = "packets_count"
    def extract(self, flow: Flow) -> float:
        return len(flow.get_packets())


class FwdPacketsCount(Feature):
    name = "fwd_packets_count"
    def extract(self, flow: Flow) -> float:
        return len(flow.get_forwardpackets())


class BwdPacketsCount(Feature):
    name = "bwd_packets_count"
    def extract(self, flow: Flow) -> float:
        return len(flow.get_backwardpackets())
