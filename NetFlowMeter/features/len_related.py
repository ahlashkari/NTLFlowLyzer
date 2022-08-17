#!/usr/bin/env python3

import numpy as np
import statistics
from scipy import stats
from .feature import Feature
from . import utils


class TotalPayloadBytes(Feature):
    name = "total_payload_bytes"
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


class PayloadBytesMax(Feature):
    name = "payload_bytes_max"
    def extract(self, flow: object) -> int:
        packets_len = [packet.get_length() for packet in flow.get_packets()]
        if packets_len:
            return max(packets_len)
        return 0


class PayloadBytesMin(Feature):
    name = "payload_bytes_min"
    def extract(self, flow: object) -> int:
        packets_len = [packet.get_length() for packet in flow.get_packets()]
        if packets_len:
            return min(packets_len)
        return 0


class PayloadBytesMean(Feature):
    name = "payload_bytes_mean"
    def extract(self, flow: object) -> float:
        packets_len = [packet.get_length() for packet in flow.get_packets()]
        if packets_len:
            return np.mean(packets_len)
        return 0


class PayloadBytesStd(Feature):
    name = "payload_bytes_std"
    def extract(self, flow: object) -> float:
        packets_len = [packet.get_length() for packet in flow.get_packets()]
        if packets_len:
            return np.std(packets_len)
        return 0


class FwdPayloadBytesMax(Feature):
    name = "fwd_payload_bytes_max"
    def extract(self, flow: object) -> int:
        packets_len = [packet.get_length() for packet in flow.get_packets()]
        if packets_len:
            return max(packets_len)
        return 0


class FwdPayloadBytesMin(Feature):
    name = "fwd_payload_bytes_min"
    def extract(self, flow: object) -> int:
        packets_len = [packet.get_length() for packet in flow.get_packets()]
        if packets_len:
            return min(packets_len)
        return 0


class FwdPayloadBytesMean(Feature):
    name = "fwd_payload_bytes_mean"
    def extract(self, flow: object) -> float:
        packets_len = [packet.get_length() for packet in flow.get_packets()]
        if packets_len:
            return np.mean(packets_len)
        return 0


class FwdPayloadBytesStd(Feature):
    name = "fwd_payload_bytes_std"
    def extract(self, flow: object) -> float:
        packets_len = [packet.get_length() for packet in flow.get_packets()]
        if packets_len:
            return np.std(packets_len)
        return 0


class BwdPayloadBytesMax(Feature):
    name = "bwd_payload_bytes_max"
    def extract(self, flow: object) -> int:
        packets_len = [packet.get_length() for packet in flow.get_packets()]
        if packets_len:
            return max(packets_len)
        return 0


class BwdPayloadBytesMin(Feature):
    name = "bwd_payload_bytes_min"
    def extract(self, flow: object) -> int:
        packets_len = [packet.get_length() for packet in flow.get_packets()]
        if packets_len:
            return min(packets_len)
        return 0


class BwdPayloadBytesMean(Feature):
    name = "bwd_payload_bytes_mean"
    def extract(self, flow: object) -> float:
        packets_len = [packet.get_length() for packet in flow.get_packets()]
        if packets_len:
            return np.mean(packets_len)
        return 0


class BwdPayloadBytesStd(Feature):
    name = "bwd_payload_bytes_std"
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
