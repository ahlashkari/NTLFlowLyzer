#!/usr/bin/env python3

from ..network_flow_capturer import Flow
from .feature import Feature
from . import utils


class BytesRate(Feature):
    name = "bytes_rate"
    def extract(self, flow: Flow) -> float:
        try:
            return utils.calculate_flow_payload_bytes(flow) / utils.calculate_flow_duration(flow)
        except ZeroDivisionError:
            return 0


# TODO: we should calculate the duration for just forward packets, not whole packets, the same is true for others
class FwdBytesRate(Feature):
    name = "fwd_bytes_rate"
    def extract(self, flow: Flow) -> float:
        try:
            return utils.calculate_fwd_flow_payload_bytes(flow) / utils.calculate_flow_duration(flow)
        except ZeroDivisionError:
            return 0


class BwdBytesRate(Feature):
    name = "bwd_bytes_rate"
    def extract(self, flow: Flow) -> float:
        try:
            return utils.calculate_bwd_flow_payload_bytes(flow) / utils.calculate_flow_duration(flow)
        except ZeroDivisionError:
            return 0


class PacketsRate(Feature):
    name = "packets_rate"
    def extract(self, flow: Flow) -> float:
        try:
            return len(flow.get_packets()) / utils.calculate_flow_duration(flow)
        except ZeroDivisionError:
            return 0


class BwdPacketsRate(Feature):
    name = "bwd_packets_rate"
    def extract(self, flow: Flow) -> float:
        try:
            return len(flow.get_backwardpackets()) / utils.calculate_flow_duration(flow)
        except ZeroDivisionError:
                return 0


class FwdPacketsRate(Feature):
    name = "fwd_packets_rate"
    def extract(self, flow: Flow) -> float:
        try:
            return len(flow.get_forwardpackets()) / utils.calculate_flow_duration(flow)
        except ZeroDivisionError:
            return 0


class DownUpRate(Feature):
    name = "down_up_rate"
    def extract(self, flow: Flow) -> float:
        if len(flow.get_forwardpackets()) > 0:
            return len(flow.get_backwardpackets()) / len(flow.get_forwardpackets())
        return 0
