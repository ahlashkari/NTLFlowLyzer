#!/usr/bin/env python3

from .feature import Feature
from . import utils


class BytesRate(Feature):
    name = "bytes_rate"
    def extract(self, flow: object) -> float:
        try:
            return utils.calculate_flow_payload_bytes(flow) / utils.calculate_flow_duration(flow)
        except ZeroDivisionError:
            return 0


# TODO: we should calculate the duration for just forward packets, not whole packets
class FwdBytesRate(Feature):
    name = "fwd_bytes_rate"
    def extract(self, flow: object) -> float:
        try:
            return utils.calculate_fwd_flow_payload_bytes(flow) / utils.calculate_flow_duration(flow)
        except ZeroDivisionError:
            return 0


class BwdBytesRate(Feature):
    name = "bwd_bytes_rate"
    def extract(self, flow: object) -> float:
        try:
            return utils.calculate_bwd_flow_payload_bytes(flow) / utils.calculate_flow_duration(flow)
        except ZeroDivisionError:
            return 0


class PacketsRate(Feature):
    name = "packets_rate"
    def extract(self, flow: object) -> float:
        try:
            return len(flow.get_packets()) / utils.calculate_flow_duration(flow)
        except ZeroDivisionError:
            return 0


class BwdPacketsRate(Feature):
    name = "bwd_packets_rate"
    def extract(self, flow: object) -> float:
        try:
            return len(flow.get_backwardpackets()) / utils.calculate_flow_duration(flow)
        except ZeroDivisionError:
                return 0


class FwdPacketsRate(Feature):
    name = "fwd_packets_rate"
    def extract(self, flow: object) -> float:
        try:
            return len(flow.get_forwardpackets()) / utils.calculate_flow_duration(flow)
        except ZeroDivisionError:
            return 0
