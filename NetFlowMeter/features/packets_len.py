#!/usr/bin/env python3

import statistics
from scipy import stats
from .feature import Feature
from . import utils


class PayloadBytes(Feature):
    name = "payload_bytes"
    def extract(self, flow: object) -> int:
        return utils.calculate_flow_payload_bytes(flow)


class FwdTotalPayloadBytes(Feature):
    name = "fwd_total_payload_bytes"
    def extract(self, flow: object) -> int:
        return utils.calculate_fwd_flow_payload_bytes(flow)


class BwdTotalPayloadBytes(Feature):
    name = "bwd_total_payload_bytes"
    def extract(self, flow: object) -> int:
        return utils.calculate_bwd_flow_payload_bytes(flow)


class TotalBytes(Feature):
    name = "total_bytes"
    def extract(self, flow: object) -> int:
        packets_len = [packet.get_length() for packet in flow.get_packets()]
        return sum(packets_len)


class FwdTotalBytes(Feature):
    name = "fwd_total_bytes"
    def extract(self, flow: object) -> int:
        packets_len = [packet.get_length() for packet in flow.get_forwardpackets()]
        return sum(packets_len)


class BwdTotalBytes(Feature):
    name = "bwd_total_bytes"
    def extract(self, flow: object) -> int:
        packets_len = [packet.get_length() for packet in flow.get_backwardpackets()]
        return sum(packets_len)


class PacketsLenMax(Feature):
    name = "packets_len_max"
    def extract(self, flow: object) -> int:
        packets_len = [packet.get_length() for packet in flow.get_packets()]
        if packets_len:
            return max(packets_len)
        return 0


class PacketsLenMin(Feature):
    name = "packets_len_min"
    def extract(self, flow: object) -> int:
        packets_len = [packet.get_length() for packet in flow.get_packets()]
        if packets_len:
            return min(packets_len)
        return 0


class PacketsLenMean(Feature):
    name = "packets_len_mean"
    def extract(self, flow: object) -> float:
        packets_len = [packet.get_length() for packet in flow.get_packets()]
        if packets_len:
            return np.mean(packets_len)
        return 0


class PacketsLenStd(Feature):
    name = "packets_len_std"
    def extract(self, flow: object) -> float:
        packets_len = [packet.get_length() for packet in flow.get_packets()]
        if packets_len:
            return np.std(packets_len)
        return 0


class FwdAvgSegmentSize(Feature):
    name = "fwd_avg_segment_size"
    def extract(self, flow: object) -> float:
        try:
            return utils.calculate_fwd_flow_payload_bytes(flow) / len(flow.get_forwardpackets())
        except ZeroDivisionError:
            return 0


class BwdAvgSegmentSize(Feature):
    name = "bwd_avg_segment_size"
    def extract(self, flow: object) -> float:
        try:
            return utils.calculate_bwd_flow_payload_bytes(flow) / len(flow.get_backwardpackets())
        except ZeroDivisionError:
            return 0


class AvgSegmentSize(Feature):
    name = "avg_segment_size"
    def extract(self, flow: object) -> float:
        try:
            return utils.calculate_flow_payload_bytes(flow) / len(flow.get_packets())
        except ZeroDivisionError:
            return 0
