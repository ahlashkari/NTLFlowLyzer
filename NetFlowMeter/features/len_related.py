#!/usr/bin/env python3

import statistics
from ..net_flow_capturer import Flow
from .feature import Feature
from . import utils


class TotalPayloadBytes(Feature):
    name = "total_payload_bytes"
    def extract(self, flow: Flow) -> int:
        return utils.calculate_flow_payload_bytes(flow)


class FwdTotalPayloadBytes(Feature):
    name = "fwd_total_payload_bytes"
    def extract(self, flow: Flow) -> int:
        return utils.calculate_fwd_flow_payload_bytes(flow)


class BwdTotalPayloadBytes(Feature):
    name = "bwd_total_payload_bytes"
    def extract(self, flow: Flow) -> int:
        return utils.calculate_bwd_flow_payload_bytes(flow)


class PayloadBytesMax(Feature):
    name = "payload_bytes_max"
    def extract(self, flow: Flow) -> int:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_packets()]
        if packets_len:
            return max(packets_len)
        return 0


class PayloadBytesMin(Feature):
    name = "payload_bytes_min"
    def extract(self, flow: Flow) -> int:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_packets()]
        if packets_len:
            return min(packets_len)
        return 0


class PayloadBytesMean(Feature):
    name = "payload_bytes_mean"
    def extract(self, flow: Flow) -> float:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_packets()]
        if packets_len:
            return format(statistics.mean(packets_len), self.floating_point_unit)
        return 0


class PayloadBytesStd(Feature):
    name = "payload_bytes_std"
    def extract(self, flow: Flow) -> float:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_packets()]
        if packets_len:
            return format(statistics.pstdev(packets_len), self.floating_point_unit)
        return 0


class PayloadBytesVariance(Feature):
    name = "payload_bytes_variance"
    def extract(self, flow: Flow) -> float:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_packets()]
        return format(statistics.pvariance(packets_len), self.floating_point_unit)


class FwdPayloadBytesMax(Feature):
    name = "fwd_payload_bytes_max"
    def extract(self, flow: Flow) -> int:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_packets()]
        if packets_len:
            return max(packets_len)
        return 0


class FwdPayloadBytesMin(Feature):
    name = "fwd_payload_bytes_min"
    def extract(self, flow: Flow) -> int:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_packets()]
        if packets_len:
            return min(packets_len)
        return 0


class FwdPayloadBytesMean(Feature):
    name = "fwd_payload_bytes_mean"
    def extract(self, flow: Flow) -> float:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_packets()]
        if packets_len:
            return format(statistics.mean(packets_len), self.floating_point_unit)
        return 0


class FwdPayloadBytesStd(Feature):
    name = "fwd_payload_bytes_std"
    def extract(self, flow: Flow) -> float:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_packets()]
        if packets_len:
            return format(statistics.pstdev(packets_len), self.floating_point_unit)
        return 0


class FwdPayloadBytesVariance(Feature):
    name = "fwd_payload_bytes_variance"
    def extract(self, flow: Flow) -> float:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_forwardpackets()]
        if len(packets_len) > 0:
            return format(statistics.pvariance(packets_len), self.floating_point_unit)
        return 0


class BwdPayloadBytesMax(Feature):
    name = "bwd_payload_bytes_max"
    def extract(self, flow: Flow) -> int:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_packets()]
        if packets_len:
            return max(packets_len)
        return 0


class BwdPayloadBytesMin(Feature):
    name = "bwd_payload_bytes_min"
    def extract(self, flow: Flow) -> int:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_packets()]
        if packets_len:
            return min(packets_len)
        return 0


class BwdPayloadBytesMean(Feature):
    name = "bwd_payload_bytes_mean"
    def extract(self, flow: Flow) -> float:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_packets()]
        if packets_len:
            return format(statistics.mean(packets_len), self.floating_point_unit)
        return 0


class BwdPayloadBytesStd(Feature):
    name = "bwd_payload_bytes_std"
    def extract(self, flow: Flow) -> float:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_packets()]
        if packets_len:
            return format(statistics.pstdev(packets_len), self.floating_point_unit)
        return 0


class BwdPayloadBytesVariance(Feature):
    name = "bwd_payload_bytes_variance"
    def extract(self, flow: Flow) -> float:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_backwardpackets()]
        if len(packets_len) > 0:
            return format(statistics.pvariance(packets_len), self.floating_point_unit)
        return 0


class FwdAvgSegmentSize(Feature):
    name = "fwd_avg_segment_size"
    def extract(self, flow: Flow) -> float:
        try:
            return utils.calculate_fwd_flow_payload_bytes(flow) / len(flow.get_forwardpackets())
        except ZeroDivisionError:
            return 0


class BwdAvgSegmentSize(Feature):
    name = "bwd_avg_segment_size"
    def extract(self, flow: Flow) -> float:
        try:
            return utils.calculate_bwd_flow_payload_bytes(flow) / len(flow.get_backwardpackets())
        except ZeroDivisionError:
            return 0


class AvgSegmentSize(Feature):
    name = "avg_segment_size"
    def extract(self, flow: Flow) -> float:
        try:
            return utils.calculate_flow_payload_bytes(flow) / len(flow.get_packets())
        except ZeroDivisionError:
            return 0


class TotalHeaderBytes(Feature):
    name = "total_header_bytes"
    def extract(self, flow: Flow) -> int:
        return utils.calculate_flow_header_bytes(flow.get_packets())


class MaxHeaderBytes(Feature):
    name = "max_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_packets()]
        if packets_header_len:
            return max(packets_header_len)
        return 0


class MinHeaderBytes(Feature):
    name = "min_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_packets()]
        if packets_header_len:
            return min(packets_header_len)
        return 0


class MeanHeaderBytes(Feature):
    name = "mean_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_packets()]
        if packets_header_len:
            return format(statistics.mean(packets_header_len), self.floating_point_unit)
        return 0


class StdHeaderBytes(Feature):
    name = "std_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_packets()]
        if packets_header_len:
            return format(statistics.pstdev(packets_header_len), self.floating_point_unit)
        return 0


class FwdTotalHeaderBytes(Feature):
    name = "fwd_total_header_bytes"
    def extract(self, flow: Flow) -> int:
        return utils.calculate_flow_header_bytes(flow.get_forwardpackets())


class FwdMaxHeaderBytes(Feature):
    name = "fwd_max_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_forwardpackets()]
        if packets_header_len:
            return max(packets_header_len)
        return 0


class FwdMinHeaderBytes(Feature):
    name = "fwd_min_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_forwardpackets()]
        if packets_header_len:
            return min(packets_header_len)
        return 0


class FwdMeanHeaderBytes(Feature):
    name = "fwd_mean_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_forwardpackets()]
        if packets_header_len:
            return format(statistics.mean(packets_header_len), self.floating_point_unit)
        return 0


class FwdStdHeaderBytes(Feature):
    name = "fwd_std_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_forwardpackets()]
        if packets_header_len:
            return format(statistics.pstdev(packets_header_len), self.floating_point_unit)
        return 0


class BwdTotalHeaderBytes(Feature):
    name = "bwd_total_header_bytes"
    def extract(self, flow: Flow) -> int:
        return utils.calculate_flow_header_bytes(flow.get_backwardpackets())


class BwdMaxHeaderBytes(Feature):
    name = "bwd_max_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_backwardpackets()]
        if packets_header_len:
            return max(packets_header_len)
        return 0


class BwdMinHeaderBytes(Feature):
    name = "bwd_min_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_backwardpackets()]
        if packets_header_len:
            return min(packets_header_len)
        return 0


class BwdMeanHeaderBytes(Feature):
    name = "bwd_mean_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_backwardpackets()]
        if packets_header_len:
            return format(statistics.mean(packets_header_len), self.floating_point_unit)
        return 0


class BwdStdHeaderBytes(Feature):
    name = "bwd_std_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_backwardpackets()]
        if packets_header_len:
            return format(statistics.pstdev(packets_header_len), self.floating_point_unit)
        return 0


class FwdInitWinBytes(Feature):
    name = "fwd_init_win_bytes"
    def extract(self, flow: Flow) -> int:
        if len(flow.get_forwardpackets()) > 0:
            return flow.get_forwardpackets()[0].get_window_size()
        return 0


class BwdInitWinBytes(Feature):
    name = "bwd_init_win_bytes"
    def extract(self, flow: Flow) -> int:
        if len(flow.get_backwardpackets()) > 0:
            return flow.get_backwardpackets()[0].get_window_size()
        return 0