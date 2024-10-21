#!/usr/bin/env python3

from datetime import datetime
import statistics
from scipy import stats
from typing import List
from ..network_flow_capturer import Flow
from .feature import Feature
from ..network_flow_capturer.packet import Packet
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


class PayloadBytesMedian(Feature):
    name = "payload_bytes_median"
    def extract(self, flow: Flow) -> float:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_packets()]
        return format(statistics.median(packets_len), self.floating_point_unit)


class PayloadBytesSkewness(Feature):
    name = "payload_bytes_skewness"
    def extract(self, flow: Flow) -> float:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_packets()]
        return format(float(stats.skew(packets_len)), self.floating_point_unit)


class PayloadBytesCov(Feature):
    name = "payload_bytes_cov"
    def extract(self, flow: Flow) -> float:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_packets()]
        return format(stats.variation(packets_len), self.floating_point_unit)


class PayloadBytesMode(Feature):
    name = "payload_bytes_mode"
    def extract(self, flow: Flow) -> float:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_packets()]
        return format(float(stats.mode(packets_len)[0]), self.floating_point_unit)


class FwdPayloadBytesMax(Feature):
    name = "fwd_payload_bytes_max"
    def extract(self, flow: Flow) -> int:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_forwardpackets()]
        if packets_len:
            return max(packets_len)
        return 0


class FwdPayloadBytesMin(Feature):
    name = "fwd_payload_bytes_min"
    def extract(self, flow: Flow) -> int:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_forwardpackets()]
        if packets_len:
            return min(packets_len)
        return 0


class FwdPayloadBytesMean(Feature):
    name = "fwd_payload_bytes_mean"
    def extract(self, flow: Flow) -> float:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_forwardpackets()]
        if packets_len:
            return format(statistics.mean(packets_len), self.floating_point_unit)
        return 0


class FwdPayloadBytesStd(Feature):
    name = "fwd_payload_bytes_std"
    def extract(self, flow: Flow) -> float:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_forwardpackets()]
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


class FwdPayloadBytesMedian(Feature):
    name = "fwd_payload_bytes_median"
    def extract(self, flow: Flow) -> float:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_forwardpackets()]
        if len(packets_len) > 0:
            return format(statistics.median(packets_len), self.floating_point_unit)
        return 0


class FwdPayloadBytesSkewness(Feature):
    name = "fwd_payload_bytes_skewness"
    def extract(self, flow: Flow) -> float:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_forwardpackets()]
        if len(packets_len) > 0:
            return format(float(stats.skew(packets_len)), self.floating_point_unit)
        return 0


class FwdPayloadBytesCov(Feature):
    name = "fwd_payload_bytes_cov"
    def extract(self, flow: Flow) -> float:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_forwardpackets()]
        if len(packets_len) > 0:
            return format(stats.variation(packets_len), self.floating_point_unit)
        return 0


class FwdPayloadBytesMode(Feature):
    name = "fwd_payload_bytes_mode"
    def extract(self, flow: Flow) -> float:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_forwardpackets()]
        if len(packets_len) > 0:
            return format(float(stats.mode(packets_len)[0]), self.floating_point_unit)
        return 0


class BwdPayloadBytesMax(Feature):
    name = "bwd_payload_bytes_max"
    def extract(self, flow: Flow) -> int:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_backwardpackets()]
        if packets_len:
            return max(packets_len)
        return 0


class BwdPayloadBytesMin(Feature):
    name = "bwd_payload_bytes_min"
    def extract(self, flow: Flow) -> int:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_backwardpackets()]
        if packets_len:
            return min(packets_len)
        return 0


class BwdPayloadBytesMean(Feature):
    name = "bwd_payload_bytes_mean"
    def extract(self, flow: Flow) -> float:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_backwardpackets()]
        if packets_len:
            return format(statistics.mean(packets_len), self.floating_point_unit)
        return 0


class BwdPayloadBytesStd(Feature):
    name = "bwd_payload_bytes_std"
    def extract(self, flow: Flow) -> float:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_backwardpackets()]
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


class BwdPayloadBytesMedian(Feature):
    name = "bwd_payload_bytes_median"
    def extract(self, flow: Flow) -> float:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_backwardpackets()]
        if len(packets_len) > 0:
            return format(statistics.median(packets_len), self.floating_point_unit)
        return 0


class BwdPayloadBytesSkewness(Feature):
    name = "bwd_payload_bytes_skewness"
    def extract(self, flow: Flow) -> float:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_backwardpackets()]
        if len(packets_len) > 0:
            return format(float(stats.skew(packets_len)), self.floating_point_unit)
        return 0


class BwdPayloadBytesCov(Feature):
    name = "bwd_payload_bytes_cov"
    def extract(self, flow: Flow) -> float:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_backwardpackets()]
        if len(packets_len) > 0:
            return format(stats.variation(packets_len), self.floating_point_unit)
        return 0


class BwdPayloadBytesMode(Feature):
    name = "bwd_payload_bytes_mode"
    def extract(self, flow: Flow) -> float:
        packets_len = [packet.get_payloadbytes() for packet in flow.get_backwardpackets()]
        if len(packets_len) > 0:
            return format(float(stats.mode(packets_len)[0]), self.floating_point_unit)
        return 0


class FwdSegmentSizeMean(Feature):
    name = "fwd_segment_size_mean"
    def extract(self, flow: Flow) -> float:
        packets_segment_size = [packet.get_segment_size() for packet in flow.get_forwardpackets()]
        if packets_segment_size:
            return format(statistics.mean(packets_segment_size), self.floating_point_unit)
        return 0


class FwdSegmentSizeMax(Feature):
    name = "fwd_segment_size_max"
    def extract(self, flow: Flow) -> float:
        packets_segment_size = [packet.get_segment_size() for packet in flow.get_forwardpackets()]
        if packets_segment_size:
            return max(packets_segment_size)
        return 0


class FwdSegmentSizeMin(Feature):
    name = "fwd_segment_size_min"
    def extract(self, flow: Flow) -> float:
        packets_segment_size = [packet.get_segment_size() for packet in flow.get_forwardpackets()]
        if packets_segment_size:
            return min(packets_segment_size)
        return 0


class FwdSegmentSizeStd(Feature):
    name = "fwd_segment_size_std"
    def extract(self, flow: Flow) -> float:
        packets_segment_size = [packet.get_segment_size() for packet in flow.get_forwardpackets()]
        if packets_segment_size:
            return format(statistics.pstdev(packets_segment_size), self.floating_point_unit)
        return 0


class FwdSegmentSizeVariance(Feature):
    name = "fwd_segment_size_variance"
    def extract(self, flow: Flow) -> float:
        packets_segment_size = [packet.get_segment_size() for packet in flow.get_forwardpackets()]
        if packets_segment_size:
            return format(statistics.pvariance(packets_segment_size), self.floating_point_unit)
        return 0


class FwdSegmentSizeMedian(Feature):
    name = "fwd_segment_size_median"
    def extract(self, flow: Flow) -> float:
        packets_segment_size = [packet.get_segment_size() for packet in flow.get_forwardpackets()]
        if packets_segment_size:
            return format(statistics.median(packets_segment_size), self.floating_point_unit)
        return 0


class FwdSegmentSizeSkewness(Feature):
    name = "fwd_segment_size_skewness"
    def extract(self, flow: Flow) -> float:
        packets_segment_size = [packet.get_segment_size() for packet in flow.get_forwardpackets()]
        if packets_segment_size:
            return format(float(stats.skew(packets_segment_size)), self.floating_point_unit)
        return 0


class FwdSegmentSizeCov(Feature):
    name = "fwd_segment_size_cov"
    def extract(self, flow: Flow) -> float:
        packets_segment_size = [packet.get_segment_size() for packet in flow.get_forwardpackets()]
        if packets_segment_size:
            return format(stats.variation(packets_segment_size), self.floating_point_unit)
        return 0


class FwdSegmentSizeMode(Feature):
    name = "fwd_segment_size_mode"
    def extract(self, flow: Flow) -> float:
        packets_segment_size = [packet.get_segment_size() for packet in flow.get_forwardpackets()]
        if packets_segment_size:
            return format(float(stats.mode(packets_segment_size)[0]), self.floating_point_unit)
        return 0


class BwdSegmentSizeMean(Feature):
    name = "bwd_segment_size_mean"
    def extract(self, flow: Flow) -> float:
        packets_segment_size = [packet.get_segment_size() for packet in flow.get_backwardpackets()]
        if packets_segment_size:
            return format(statistics.mean(packets_segment_size), self.floating_point_unit)
        return 0


class BwdSegmentSizeMax(Feature):
    name = "bwd_segment_size_max"
    def extract(self, flow: Flow) -> float:
        packets_segment_size = [packet.get_segment_size() for packet in flow.get_backwardpackets()]
        if packets_segment_size:
            return max(packets_segment_size)
        return 0


class BwdSegmentSizeMin(Feature):
    name = "bwd_segment_size_min"
    def extract(self, flow: Flow) -> float:
        packets_segment_size = [packet.get_segment_size() for packet in flow.get_backwardpackets()]
        if packets_segment_size:
            return min(packets_segment_size)
        return 0


class BwdSegmentSizeStd(Feature):
    name = "bwd_segment_size_std"
    def extract(self, flow: Flow) -> float:
        packets_segment_size = [packet.get_segment_size() for packet in flow.get_backwardpackets()]
        if packets_segment_size:
            return format(statistics.pstdev(packets_segment_size), self.floating_point_unit)
        return 0


class BwdSegmentSizeVariance(Feature):
    name = "bwd_segment_size_variance"
    def extract(self, flow: Flow) -> float:
        packets_segment_size = [packet.get_segment_size() for packet in flow.get_backwardpackets()]
        if packets_segment_size:
            return format(statistics.pvariance(packets_segment_size), self.floating_point_unit)
        return 0


class BwdSegmentSizeMedian(Feature):
    name = "bwd_segment_size_median"
    def extract(self, flow: Flow) -> float:
        packets_segment_size = [packet.get_segment_size() for packet in flow.get_backwardpackets()]
        if packets_segment_size:
            return format(statistics.median(packets_segment_size), self.floating_point_unit)
        return 0


class BwdSegmentSizeSkewness(Feature):
    name = "bwd_segment_size_skewness"
    def extract(self, flow: Flow) -> float:
        packets_segment_size = [packet.get_segment_size() for packet in flow.get_backwardpackets()]
        if packets_segment_size:
            return format(float(stats.skew(packets_segment_size)), self.floating_point_unit)
        return 0


class BwdSegmentSizeCov(Feature):
    name = "bwd_segment_size_cov"
    def extract(self, flow: Flow) -> float:
        packets_segment_size = [packet.get_segment_size() for packet in flow.get_backwardpackets()]
        if packets_segment_size:
            return format(stats.variation(packets_segment_size), self.floating_point_unit)
        return 0


class BwdSegmentSizeMode(Feature):
    name = "bwd_segment_size_mode"
    def extract(self, flow: Flow) -> float:
        packets_segment_size = [packet.get_segment_size() for packet in flow.get_backwardpackets()]
        if packets_segment_size:
            return format(float(stats.mode(packets_segment_size)[0]), self.floating_point_unit)
        return 0


class SegmentSizeMean(Feature):
    name = "segment_size_mean"
    def extract(self, flow: Flow) -> float:
        packets_segment_size = [packet.get_segment_size() for packet in flow.get_packets()]
        if packets_segment_size:
            return format(statistics.mean(packets_segment_size), self.floating_point_unit)
        return 0


class SegmentSizeMax(Feature):
    name = "segment_size_max"
    def extract(self, flow: Flow) -> float:
        packets_segment_size = [packet.get_segment_size() for packet in flow.get_packets()]
        if packets_segment_size:
            return max(packets_segment_size)
        return 0


class SegmentSizeMin(Feature):
    name = "segment_size_min"
    def extract(self, flow: Flow) -> float:
        packets_segment_size = [packet.get_segment_size() for packet in flow.get_packets()]
        if packets_segment_size:
            return min(packets_segment_size)
        return 0


class SegmentSizeStd(Feature):
    name = "segment_size_std"
    def extract(self, flow: Flow) -> float:
        packets_segment_size = [packet.get_segment_size() for packet in flow.get_packets()]
        if packets_segment_size:
            return format(statistics.pstdev(packets_segment_size), self.floating_point_unit)
        return 0


class SegmentSizeVariance(Feature):
    name = "segment_size_variance"
    def extract(self, flow: Flow) -> float:
        packets_segment_size = [packet.get_segment_size() for packet in flow.get_packets()]
        if packets_segment_size:
            return format(statistics.pvariance(packets_segment_size), self.floating_point_unit)
        return 0


class SegmentSizeMedian(Feature):
    name = "segment_size_median"
    def extract(self, flow: Flow) -> float:
        packets_segment_size = [packet.get_segment_size() for packet in flow.get_packets()]
        if packets_segment_size:
            return format(statistics.median(packets_segment_size), self.floating_point_unit)
        return 0


class SegmentSizeSkewness(Feature):
    name = "segment_size_skewness"
    def extract(self, flow: Flow) -> float:
        packets_segment_size = [packet.get_segment_size() for packet in flow.get_packets()]
        if packets_segment_size:
            return format(float(stats.skew(packets_segment_size)), self.floating_point_unit)
        return 0


class SegmentSizeCov(Feature):
    name = "segment_size_cov"
    def extract(self, flow: Flow) -> float:
        packets_segment_size = [packet.get_segment_size() for packet in flow.get_packets()]
        if packets_segment_size:
            return format(stats.variation(packets_segment_size), self.floating_point_unit)
        return 0


class SegmentSizeMode(Feature):
    name = "segment_size_mode"
    def extract(self, flow: Flow) -> float:
        packets_segment_size = [packet.get_segment_size() for packet in flow.get_packets()]
        if packets_segment_size:
            return format(float(stats.mode(packets_segment_size)[0]), self.floating_point_unit)
        return 0


class TotalHeaderBytes(Feature):
    name = "total_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_packets()]
        return sum(packets_header_len)


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


class MedianHeaderBytes(Feature):
    name = "median_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_packets()]
        if packets_header_len:
            return format(statistics.median(packets_header_len), self.floating_point_unit)
        return 0


class SkewnessHeaderBytes(Feature):
    name = "skewness_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_packets()]
        if packets_header_len:
            return format(float(stats.skew(packets_header_len)), self.floating_point_unit)
        return 0


class CoVHeaderBytes(Feature):
    name = "cov_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_packets()]
        if packets_header_len:
            return format(stats.variation(packets_header_len), self.floating_point_unit)
        return 0


class ModeHeaderBytes(Feature):
    name = "mode_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_packets()]
        if packets_header_len:
            return format(float(stats.mode(packets_header_len)[0]), self.floating_point_unit)
        return 0


class VarianceHeaderBytes(Feature):
    name = "variance_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_packets()]
        if packets_header_len:
            return format(statistics.pvariance(packets_header_len), self.floating_point_unit)
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


class FwdMedianHeaderBytes(Feature):
    name = "fwd_median_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_forwardpackets()]
        if packets_header_len:
            return format(statistics.median(packets_header_len), self.floating_point_unit)
        return 0


class FwdSkewnessHeaderBytes(Feature):
    name = "fwd_skewness_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_forwardpackets()]
        if packets_header_len:
            return format(float(stats.skew(packets_header_len)), self.floating_point_unit)
        return 0


class FwdCoVHeaderBytes(Feature):
    name = "fwd_cov_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_forwardpackets()]
        if packets_header_len:
            return format(stats.variation(packets_header_len), self.floating_point_unit)
        return 0


class FwdModeHeaderBytes(Feature):
    name = "fwd_mode_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_forwardpackets()]
        if packets_header_len:
            return format(float(stats.mode(packets_header_len)[0]), self.floating_point_unit)
        return 0


class FwdVarianceHeaderBytes(Feature):
    name = "fwd_variance_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_forwardpackets()]
        if packets_header_len:
            return format(statistics.pvariance(packets_header_len), self.floating_point_unit)
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


class BwdMedianHeaderBytes(Feature):
    name = "bwd_median_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_backwardpackets()]
        if packets_header_len:
            return format(statistics.median(packets_header_len), self.floating_point_unit)
        return 0


class BwdSkewnessHeaderBytes(Feature):
    name = "bwd_skewness_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_backwardpackets()]
        if packets_header_len:
            return format(float(stats.skew(packets_header_len)), self.floating_point_unit)
        return 0


class BwdCoVHeaderBytes(Feature):
    name = "bwd_cov_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_backwardpackets()]
        if packets_header_len:
            return format(stats.variation(packets_header_len), self.floating_point_unit)
        return 0


class BwdModeHeaderBytes(Feature):
    name = "bwd_mode_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_backwardpackets()]
        if packets_header_len:
            return format(float(stats.mode(packets_header_len)[0]), self.floating_point_unit)
        return 0


class BwdVarianceHeaderBytes(Feature):
    name = "bwd_variance_header_bytes"
    def extract(self, flow: Flow) -> int:
        packets_header_len = [packet.get_header_size() for packet in flow.get_backwardpackets()]
        if packets_header_len:
            return format(statistics.pvariance(packets_header_len), self.floating_point_unit)
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


class PacketsDeltaLenBase(Feature):
    def __get_packets_delta_len(self, packets: List[Packet]):
        packets_timestamp = [datetime.fromtimestamp(float(packet.get_timestamp())) for packet in packets]
        packets_sorted = [packet for _, packet in sorted(zip(packets_timestamp, packets))]
        packets_len = [float(packet.get_length()) for packet in packets_sorted]
        packets_del_len = [pkt - pkt_prev for pkt_prev, pkt in
                           zip(packets_len[:-1], packets_len[1:])]
        return packets_del_len


    def get_receiving_delta(self, flow: Flow) -> list:
        return self.__get_packets_delta_len(flow.get_backwardpackets())

    def get_sending_delta(self, flow: Flow) -> list:
        return self.__get_packets_delta_len(flow.get_forwardpackets())

    def get_all_delta(self, flow: Flow) -> list:
        return self.__get_packets_delta_len(flow.get_packets())


    def __get_headers_delta_len(self, packets: List[Packet]):
        packets_timestamp = [packet.get_timestamp() for packet in packets]
        packets_sorted = [packet for _, packet in sorted(zip(packets_timestamp, packets))]
        packets_len = [float(packet.get_header_size()) for packet in packets_sorted]
        packets_del_len = [pkt - pkt_prev for pkt_prev, pkt in
                           zip(packets_len[:-1], packets_len[1:])]
        return packets_del_len


    def get_receiving_headers_delta(self, flow: Flow) -> list:
        return self.__get_headers_delta_len(flow.get_backwardpackets())

    def get_sending_headers_delta(self, flow: Flow) -> list:
        return self.__get_headers_delta_len(flow.get_forwardpackets())

    def get_all_headers_delta(self, flow: Flow) -> list:
        return self.__get_headers_delta_len(flow.get_packets())


    def __get_payload_delta_len(self, packets: List[Packet]):
        packets_timestamp = [packet.get_timestamp() for packet in packets]
        packets_sorted = [packet for _, packet in sorted(zip(packets_timestamp, packets))]
        packets_len = [float(packet.get_payloadbytes()) for packet in packets_sorted]
        packets_del_len = [pkt - pkt_prev for pkt_prev, pkt in
                           zip(packets_len[:-1], packets_len[1:])]
        return packets_del_len

    def get_receiving_payload_delta(self, flow: Flow) -> list:
        return self.__get_payload_delta_len(flow.get_backwardpackets())

    def get_sending_payload_delta(self, flow: Flow) -> list:
        return self.__get_payload_delta_len(flow.get_forwardpackets())

    def get_all_payload_delta(self, flow: Flow) -> list:
        return self.__get_payload_delta_len(flow.get_packets())


class PacketsDeltaLenMin(PacketsDeltaLenBase):
    name = "min_packets_delta_len"
    def extract(self, flow: Flow) -> int:
        packets_del_len = super().get_all_delta(flow)
        return min(packets_del_len) if len(packets_del_len) > 0 else 0


class PacketsDeltaLenMax(PacketsDeltaLenBase):
    name = "max_packets_delta_len"
    def extract(self, flow: Flow) -> int:
        packets_del_len = super().get_all_delta(flow)
        return max(packets_del_len) if len(packets_del_len) > 0 else 0


class PacketsDeltaLenMean(PacketsDeltaLenBase):
    name = "mean_packets_delta_len"
    def extract(self, flow: Flow) -> float:
        packets_del_len = super().get_all_delta(flow)
        if len(packets_del_len) > 0:
            return format(statistics.mean(packets_del_len), self.floating_point_unit)
        return 0


class PacketsDeltaLenMode(PacketsDeltaLenBase):
    name = "mode_packets_delta_len"
    def extract(self, flow: Flow) -> float:
        packets_del_len = super().get_all_delta(flow)
        if len(packets_del_len) > 0:
            return format(float(stats.mode(packets_del_len)[0]), self.floating_point_unit)
        return 0


class PacketsDeltaLenVariance(PacketsDeltaLenBase):
    name = "variance_packets_delta_len"
    def extract(self, flow: Flow) -> float:
        packets_del_len = super().get_all_delta(flow)
        if len(packets_del_len) > 0:
            return format(statistics.pvariance(packets_del_len), self.floating_point_unit)
        return 0


class PacketsDeltaLenStd(PacketsDeltaLenBase):
    name = "std_packets_delta_len"
    def extract(self, flow: Flow) -> float:
        packets_del_len = super().get_all_delta(flow)
        if len(packets_del_len) > 0:
            return format(statistics.pstdev(packets_del_len), self.floating_point_unit)
        return 0


class PacketsDeltaLenMedian(PacketsDeltaLenBase):
    name = "median_packets_delta_len"
    def extract(self, flow: Flow) -> float:
        packets_del_len = super().get_all_delta(flow)
        if len(packets_del_len) > 0:
            return format(statistics.median(packets_del_len), self.floating_point_unit)
        return 0


class PacketsDeltaLenSkewness(PacketsDeltaLenBase):
    name = "skewness_packets_delta_len"
    def extract(self, flow: Flow) -> float:
        packets_del_len = super().get_all_delta(flow)
        if len(packets_del_len) > 0:
            return format(float(stats.skew(packets_del_len)), self.floating_point_unit)
        return 0


class PacketsDeltaLenCoV(PacketsDeltaLenBase):
    name = "cov_packets_delta_len"
    def extract(self, flow: Flow) -> float:
        packets_del_len = super().get_all_delta(flow)
        if len(packets_del_len) > 0:
            return format(stats.variation(packets_del_len), self.floating_point_unit)
        return 0


class BwdPacketsDeltaLenMin(PacketsDeltaLenBase):
    name = "min_bwd_packets_delta_len"
    def extract(self, flow: Flow) -> int:
        receiving_packets_del_len = super().get_receiving_delta(flow)
        return min(receiving_packets_del_len) if len(receiving_packets_del_len) > 0 else 0


class BwdPacketsDeltaLenMax(PacketsDeltaLenBase):
    name = "max_bwd_packets_delta_len"
    def extract(self, flow: Flow) -> int:
        receiving_packets_del_len = super().get_receiving_delta(flow)
        return max(receiving_packets_del_len) if len(receiving_packets_del_len) > 0 else 0


class BwdPacketsDeltaLenMean(PacketsDeltaLenBase):
    name = "mean_bwd_packets_delta_len"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_len = super().get_receiving_delta(flow)
        if len(receiving_packets_del_len) > 0:
            return format(statistics.mean(receiving_packets_del_len), self.floating_point_unit)
        return 0


class BwdPacketsDeltaLenMode(PacketsDeltaLenBase):
    name = "mode_bwd_packets_delta_len"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_len = super().get_receiving_delta(flow)
        if len(receiving_packets_del_len) > 0:
            return format(float(stats.mode(receiving_packets_del_len)[0]), self.floating_point_unit)
        return 0


class BwdPacketsDeltaLenVariance(PacketsDeltaLenBase):
    name = "variance_bwd_packets_delta_len"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_len = super().get_receiving_delta(flow)
        if len(receiving_packets_del_len) > 0:
            return format(statistics.pvariance(receiving_packets_del_len), self.floating_point_unit)
        return 0


class BwdPacketsDeltaLenStd(PacketsDeltaLenBase):
    name = "std_bwd_packets_delta_len"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_len = super().get_receiving_delta(flow)
        if len(receiving_packets_del_len) > 0:
            return format(statistics.pstdev(receiving_packets_del_len), self.floating_point_unit)
        return 0


class BwdPacketsDeltaLenMedian(PacketsDeltaLenBase):
    name = "median_bwd_packets_delta_len"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_len = super().get_receiving_delta(flow)
        if len(receiving_packets_del_len) > 0:
            return format(statistics.median(receiving_packets_del_len), self.floating_point_unit)
        return 0


class BwdPacketsDeltaLenSkewness(PacketsDeltaLenBase):
    name = "skewness_bwd_packets_delta_len"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_len = super().get_receiving_delta(flow)
        if len(receiving_packets_del_len) > 0:
            return format(float(stats.skew(receiving_packets_del_len)), self.floating_point_unit)
        return 0


class BwdPacketsDeltaLenCoV(PacketsDeltaLenBase):
    name = "cov_bwd_packets_delta_len"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_len = super().get_receiving_delta(flow)
        if len(receiving_packets_del_len) > 0:
            return format(stats.variation(receiving_packets_del_len), self.floating_point_unit)
        return 0


class FwdPacketsDeltaLenMin(PacketsDeltaLenBase):
    name = "min_fwd_packets_delta_len"
    def extract(self, flow: Flow) -> int:
        sending_packets_del_len = super().get_sending_delta(flow)
        return min(sending_packets_del_len) if len(sending_packets_del_len) > 0 else 0


class FwdPacketsDeltaLenMax(PacketsDeltaLenBase):
    name = "max_fwd_packets_delta_len"
    def extract(self, flow: Flow) -> int:
        sending_packets_del_len = super().get_sending_delta(flow)
        return max(sending_packets_del_len) if len(sending_packets_del_len) > 0 else 0


class FwdPacketsDeltaLenMean(PacketsDeltaLenBase):
    name = "mean_fwd_packets_delta_len"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_len = super().get_sending_delta(flow)
        if len(sending_packets_del_len) > 0:
            return format(statistics.mean(sending_packets_del_len), self.floating_point_unit)
        return 0


class FwdPacketsDeltaLenMode(PacketsDeltaLenBase):
    name = "mode_fwd_packets_delta_len"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_len = super().get_sending_delta(flow)
        if len(sending_packets_del_len) > 0:
            return format(float(stats.mode(sending_packets_del_len)[0]), self.floating_point_unit)
        return 0


class FwdPacketsDeltaLenVariance(PacketsDeltaLenBase):
    name = "variance_fwd_packets_delta_len"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_len = super().get_sending_delta(flow)
        if len(sending_packets_del_len) > 0:
            return format(statistics.pvariance(sending_packets_del_len), self.floating_point_unit)
        return 0


class FwdPacketsDeltaLenStd(PacketsDeltaLenBase):
    name = "std_fwd_packets_delta_len"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_len = super().get_sending_delta(flow)
        if len(sending_packets_del_len) > 0:
            return format(statistics.pstdev(sending_packets_del_len), self.floating_point_unit)
        return 0


class FwdPacketsDeltaLenMedian(PacketsDeltaLenBase):
    name = "median_fwd_packets_delta_len"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_len = super().get_sending_delta(flow)
        if len(sending_packets_del_len) > 0:
            return format(statistics.median(sending_packets_del_len), self.floating_point_unit)
        return 0


class FwdPacketsDeltaLenSkewness(PacketsDeltaLenBase):
    name = "skewness_fwd_packets_delta_len"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_len = super().get_sending_delta(flow)
        if len(sending_packets_del_len) > 0:
            return format(float(stats.skew(sending_packets_del_len)), self.floating_point_unit)
        return 0


class FwdPacketsDeltaLenCoV(PacketsDeltaLenBase):
    name = "cov_fwd_packets_delta_len"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_len = super().get_sending_delta(flow)
        if len(sending_packets_del_len) > 0:
            return format(stats.variation(sending_packets_del_len), self.floating_point_unit)
        return 0

# Delta Packet Header

class HeaderBytesDeltaLenMin(PacketsDeltaLenBase):
    name = "min_header_bytes_delta_len"
    def extract(self, flow: Flow) -> int:
        packets_headers__del_len = super().get_all_headers_delta(flow)
        return min(packets_headers__del_len) if len(packets_headers__del_len) > 0 else 0


class HeaderBytesDeltaLenMax(PacketsDeltaLenBase):
    name = "max_header_bytes_delta_len"
    def extract(self, flow: Flow) -> int:
        packets_del_len = super().get_all_headers_delta(flow)
        return max(packets_del_len) if len(packets_del_len) > 0 else 0


class HeaderBytesDeltaLenMean(PacketsDeltaLenBase):
    name = "mean_header_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        packets_del_len = super().get_all_headers_delta(flow)
        if len(packets_del_len) > 0:
            return format(statistics.mean(packets_del_len), self.floating_point_unit)
        return 0


class HeaderBytesDeltaLenMode(PacketsDeltaLenBase):
    name = "mode_header_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        packets_del_len = super().get_all_headers_delta(flow)
        if len(packets_del_len) > 0:
            return format(float(stats.mode(packets_del_len)[0]), self.floating_point_unit)
        return 0


class HeaderBytesDeltaLenVariance(PacketsDeltaLenBase):
    name = "variance_header_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        packets_del_len = super().get_all_headers_delta(flow)
        if len(packets_del_len) > 0:
            return format(statistics.pvariance(packets_del_len), self.floating_point_unit)
        return 0


class HeaderBytesDeltaLenStd(PacketsDeltaLenBase):
    name = "std_header_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        packets_del_len = super().get_all_headers_delta(flow)
        if len(packets_del_len) > 0:
            return format(statistics.pstdev(packets_del_len), self.floating_point_unit)
        return 0


class HeaderBytesDeltaLenMedian(PacketsDeltaLenBase):
    name = "median_header_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        packets_del_len = super().get_all_headers_delta(flow)
        if len(packets_del_len) > 0:
            return format(statistics.median(packets_del_len), self.floating_point_unit)
        return 0


class HeaderBytesDeltaLenSkewness(PacketsDeltaLenBase):
    name = "skewness_header_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        packets_del_len = super().get_all_headers_delta(flow)
        if len(packets_del_len) > 0:
            return format(float(stats.skew(packets_del_len)), self.floating_point_unit)
        return 0


class HeaderBytesDeltaLenCoV(PacketsDeltaLenBase):
    name = "cov_header_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        packets_del_len = super().get_all_headers_delta(flow)
        if len(packets_del_len) > 0:
            return format(stats.variation(packets_del_len), self.floating_point_unit)
        return 0


class BwdHeaderBytesDeltaLenMin(PacketsDeltaLenBase):
    name = "min_bwd_header_bytes_delta_len"
    def extract(self, flow: Flow) -> int:
        receiving_packets_del_len = super().get_receiving_headers_delta(flow)
        return min(receiving_packets_del_len) if len(receiving_packets_del_len) > 0 else 0


class BwdHeaderBytesDeltaLenMax(PacketsDeltaLenBase):
    name = "max_bwd_header_bytes_delta_len"
    def extract(self, flow: Flow) -> int:
        receiving_packets_del_len = super().get_receiving_headers_delta(flow)
        return max(receiving_packets_del_len) if len(receiving_packets_del_len) > 0 else 0


class BwdHeaderBytesDeltaLenMean(PacketsDeltaLenBase):
    name = "mean_bwd_header_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_len = super().get_receiving_headers_delta(flow)
        if len(receiving_packets_del_len) > 0:
            return format(statistics.mean(receiving_packets_del_len), self.floating_point_unit)
        return 0


class BwdHeaderBytesDeltaLenMode(PacketsDeltaLenBase):
    name = "mode_bwd_header_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_len = super().get_receiving_headers_delta(flow)
        if len(receiving_packets_del_len) > 0:
            return format(float(stats.mode(receiving_packets_del_len)[0]), self.floating_point_unit)
        return 0


class BwdHeaderBytesDeltaLenVariance(PacketsDeltaLenBase):
    name = "variance_bwd_header_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_len = super().get_receiving_headers_delta(flow)
        if len(receiving_packets_del_len) > 0:
            return format(statistics.pvariance(receiving_packets_del_len), self.floating_point_unit)
        return 0


class BwdHeaderBytesDeltaLenStd(PacketsDeltaLenBase):
    name = "std_bwd_header_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_len = super().get_receiving_headers_delta(flow)
        if len(receiving_packets_del_len) > 0:
            return format(statistics.pstdev(receiving_packets_del_len), self.floating_point_unit)
        return 0


class BwdHeaderBytesDeltaLenMedian(PacketsDeltaLenBase):
    name = "median_bwd_header_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_len = super().get_receiving_headers_delta(flow)
        if len(receiving_packets_del_len) > 0:
            return format(statistics.median(receiving_packets_del_len), self.floating_point_unit)
        return 0


class BwdHeaderBytesDeltaLenSkewness(PacketsDeltaLenBase):
    name = "skewness_bwd_header_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_len = super().get_receiving_headers_delta(flow)
        if len(receiving_packets_del_len) > 0:
            return format(float(stats.skew(receiving_packets_del_len)), self.floating_point_unit)
        return 0


class BwdHeaderBytesDeltaLenCoV(PacketsDeltaLenBase):
    name = "cov_bwd_header_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_len = super().get_receiving_headers_delta(flow)
        if len(receiving_packets_del_len) > 0:
            return format(stats.variation(receiving_packets_del_len), self.floating_point_unit)
        return 0


class FwdHeaderBytesDeltaLenMin(PacketsDeltaLenBase):
    name = "min_fwd_header_bytes_delta_len"
    def extract(self, flow: Flow) -> int:
        sending_packets_del_len = super().get_sending_headers_delta(flow)
        return min(sending_packets_del_len) if len(sending_packets_del_len) > 0 else 0


class FwdHeaderBytesDeltaLenMax(PacketsDeltaLenBase):
    name = "max_fwd_header_bytes_delta_len"
    def extract(self, flow: Flow) -> int:
        sending_packets_del_len = super().get_sending_headers_delta(flow)
        return max(sending_packets_del_len) if len(sending_packets_del_len) > 0 else 0


class FwdHeaderBytesDeltaLenMean(PacketsDeltaLenBase):
    name = "mean_fwd_header_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_len = super().get_sending_headers_delta(flow)
        if len(sending_packets_del_len) > 0:
            return format(statistics.mean(sending_packets_del_len), self.floating_point_unit)
        return 0


class FwdHeaderBytesDeltaLenMode(PacketsDeltaLenBase):
    name = "mode_fwd_header_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_len = super().get_sending_headers_delta(flow)
        if len(sending_packets_del_len) > 0:
            return format(float(stats.mode(sending_packets_del_len)[0]), self.floating_point_unit)
        return 0


class FwdHeaderBytesDeltaLenVariance(PacketsDeltaLenBase):
    name = "variance_fwd_header_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_len = super().get_sending_headers_delta(flow)
        if len(sending_packets_del_len) > 0:
            return format(statistics.pvariance(sending_packets_del_len), self.floating_point_unit)
        return 0


class FwdHeaderBytesDeltaLenStd(PacketsDeltaLenBase):
    name = "std_fwd_header_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_len = super().get_sending_headers_delta(flow)
        if len(sending_packets_del_len) > 0:
            return format(statistics.pstdev(sending_packets_del_len), self.floating_point_unit)
        return 0


class FwdHeaderBytesDeltaLenMedian(PacketsDeltaLenBase):
    name = "median_fwd_header_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_len = super().get_sending_headers_delta(flow)
        if len(sending_packets_del_len) > 0:
            return format(statistics.median(sending_packets_del_len), self.floating_point_unit)
        return 0


class FwdHeaderBytesDeltaLenSkewness(PacketsDeltaLenBase):
    name = "skewness_fwd_header_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_len = super().get_sending_headers_delta(flow)
        if len(sending_packets_del_len) > 0:
            return format(float(stats.skew(sending_packets_del_len)), self.floating_point_unit)
        return 0


class FwdHeaderBytesDeltaLenCoV(PacketsDeltaLenBase):
    name = "cov_fwd_header_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_len = super().get_sending_headers_delta(flow)
        if len(sending_packets_del_len) > 0:
            return format(stats.variation(sending_packets_del_len), self.floating_point_unit)
        return 0


# Delta Packet Payload

class PayloadBytesDeltaLenMin(PacketsDeltaLenBase):
    name = "min_payload_bytes_delta_len"
    def extract(self, flow: Flow) -> int:
        packets_headers__del_len = super().get_all_payload_delta(flow)
        return min(packets_headers__del_len) if len(packets_headers__del_len) > 0 else 0


class PayloadBytesDeltaLenMax(PacketsDeltaLenBase):
    name = "max_payload_bytes_delta_len"
    def extract(self, flow: Flow) -> int:
        packets_del_len = super().get_all_payload_delta(flow)
        return max(packets_del_len) if len(packets_del_len) > 0 else 0


class PayloadBytesDeltaLenMean(PacketsDeltaLenBase):
    name = "mean_payload_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        packets_del_len = super().get_all_payload_delta(flow)
        if len(packets_del_len) > 0:
            return format(statistics.mean(packets_del_len), self.floating_point_unit)
        return 0


class PayloadBytesDeltaLenMode(PacketsDeltaLenBase):
    name = "mode_payload_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        packets_del_len = super().get_all_payload_delta(flow)
        if len(packets_del_len) > 0:
            return format(float(stats.mode(packets_del_len)[0]), self.floating_point_unit)
        return 0


class PayloadBytesDeltaLenVariance(PacketsDeltaLenBase):
    name = "variance_payload_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        packets_del_len = super().get_all_payload_delta(flow)
        if len(packets_del_len) > 0:
            return format(statistics.pvariance(packets_del_len), self.floating_point_unit)
        return 0


class PayloadBytesDeltaLenStd(PacketsDeltaLenBase):
    name = "std_payload_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        packets_del_len = super().get_all_payload_delta(flow)
        if len(packets_del_len) > 0:
            return format(statistics.pstdev(packets_del_len), self.floating_point_unit)
        return 0


class PayloadBytesDeltaLenMedian(PacketsDeltaLenBase):
    name = "median_payload_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        packets_del_len = super().get_all_payload_delta(flow)
        if len(packets_del_len) > 0:
            return format(statistics.median(packets_del_len), self.floating_point_unit)
        return 0


class PayloadBytesDeltaLenSkewness(PacketsDeltaLenBase):
    name = "skewness_payload_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        packets_del_len = super().get_all_payload_delta(flow)
        if len(packets_del_len) > 0:
            return format(float(stats.skew(packets_del_len)), self.floating_point_unit)
        return 0


class PayloadBytesDeltaLenCoV(PacketsDeltaLenBase):
    name = "cov_payload_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        packets_del_len = super().get_all_payload_delta(flow)
        if len(packets_del_len) > 0:
            return format(stats.variation(packets_del_len), self.floating_point_unit)
        return 0


class BwdPayloadBytesDeltaLenMin(PacketsDeltaLenBase):
    name = "min_bwd_payload_bytes_delta_len"
    def extract(self, flow: Flow) -> int:
        receiving_packets_del_len = super().get_receiving_payload_delta(flow)
        return min(receiving_packets_del_len) if len(receiving_packets_del_len) > 0 else 0


class BwdPayloadBytesDeltaLenMax(PacketsDeltaLenBase):
    name = "max_bwd_payload_bytes_delta_len"
    def extract(self, flow: Flow) -> int:
        receiving_packets_del_len = super().get_receiving_payload_delta(flow)
        return max(receiving_packets_del_len) if len(receiving_packets_del_len) > 0 else 0


class BwdPayloadBytesDeltaLenMean(PacketsDeltaLenBase):
    name = "mean_bwd_payload_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_len = super().get_receiving_payload_delta(flow)
        if len(receiving_packets_del_len) > 0:
            return format(statistics.mean(receiving_packets_del_len), self.floating_point_unit)
        return 0


class BwdPayloadBytesDeltaLenMode(PacketsDeltaLenBase):
    name = "mode_bwd_payload_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_len = super().get_receiving_payload_delta(flow)
        if len(receiving_packets_del_len) > 0:
            return format(float(stats.mode(receiving_packets_del_len)[0]), self.floating_point_unit)
        return 0


class BwdPayloadBytesDeltaLenVariance(PacketsDeltaLenBase):
    name = "variance_bwd_payload_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_len = super().get_receiving_payload_delta(flow)
        if len(receiving_packets_del_len) > 0:
            return format(statistics.pvariance(receiving_packets_del_len), self.floating_point_unit)
        return 0


class BwdPayloadBytesDeltaLenStd(PacketsDeltaLenBase):
    name = "std_bwd_payload_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_len = super().get_receiving_payload_delta(flow)
        if len(receiving_packets_del_len) > 0:
            return format(statistics.pstdev(receiving_packets_del_len), self.floating_point_unit)
        return 0


class BwdPayloadBytesDeltaLenMedian(PacketsDeltaLenBase):
    name = "median_bwd_payload_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_len = super().get_receiving_payload_delta(flow)
        if len(receiving_packets_del_len) > 0:
            return format(statistics.median(receiving_packets_del_len), self.floating_point_unit)
        return 0


class BwdPayloadBytesDeltaLenSkewness(PacketsDeltaLenBase):
    name = "skewness_bwd_payload_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_len = super().get_receiving_payload_delta(flow)
        if len(receiving_packets_del_len) > 0:
            return format(float(stats.skew(receiving_packets_del_len)), self.floating_point_unit)
        return 0


class BwdPayloadBytesDeltaLenCoV(PacketsDeltaLenBase):
    name = "cov_bwd_payload_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_len = super().get_receiving_payload_delta(flow)
        if len(receiving_packets_del_len) > 0:
            return format(stats.variation(receiving_packets_del_len), self.floating_point_unit)
        return 0


class FwdPayloadBytesDeltaLenMin(PacketsDeltaLenBase):
    name = "min_fwd_payload_bytes_delta_len"
    def extract(self, flow: Flow) -> int:
        sending_packets_del_len = super().get_sending_payload_delta(flow)
        return min(sending_packets_del_len) if len(sending_packets_del_len) > 0 else 0


class FwdPayloadBytesDeltaLenMax(PacketsDeltaLenBase):
    name = "max_fwd_payload_bytes_delta_len"
    def extract(self, flow: Flow) -> int:
        sending_packets_del_len = super().get_sending_payload_delta(flow)
        return max(sending_packets_del_len) if len(sending_packets_del_len) > 0 else 0


class FwdPayloadBytesDeltaLenMean(PacketsDeltaLenBase):
    name = "mean_fwd_payload_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_len = super().get_sending_payload_delta(flow)
        if len(sending_packets_del_len) > 0:
            return format(statistics.mean(sending_packets_del_len), self.floating_point_unit)
        return 0


class FwdPayloadBytesDeltaLenMode(PacketsDeltaLenBase):
    name = "mode_fwd_payload_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_len = super().get_sending_payload_delta(flow)
        if len(sending_packets_del_len) > 0:
            return format(float(stats.mode(sending_packets_del_len)[0]), self.floating_point_unit)
        return 0


class FwdPayloadBytesDeltaLenVariance(PacketsDeltaLenBase):
    name = "variance_fwd_payload_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_len = super().get_sending_payload_delta(flow)
        if len(sending_packets_del_len) > 0:
            return format(statistics.pvariance(sending_packets_del_len), self.floating_point_unit)
        return 0


class FwdPayloadBytesDeltaLenStd(PacketsDeltaLenBase):
    name = "std_fwd_payload_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_len = super().get_sending_payload_delta(flow)
        if len(sending_packets_del_len) > 0:
            return format(statistics.pstdev(sending_packets_del_len), self.floating_point_unit)
        return 0


class FwdPayloadBytesDeltaLenMedian(PacketsDeltaLenBase):
    name = "median_fwd_payload_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_len = super().get_sending_payload_delta(flow)
        if len(sending_packets_del_len) > 0:
            return format(statistics.median(sending_packets_del_len), self.floating_point_unit)
        return 0


class FwdPayloadBytesDeltaLenSkewness(PacketsDeltaLenBase):
    name = "skewness_fwd_payload_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_len = super().get_sending_payload_delta(flow)
        if len(sending_packets_del_len) > 0:
            return format(float(stats.skew(sending_packets_del_len)), self.floating_point_unit)
        return 0


class FwdPayloadBytesDeltaLenCoV(PacketsDeltaLenBase):
    name = "cov_fwd_payload_bytes_delta_len"
    def extract(self, flow: Flow) -> float:
        sending_packets_payload_del_len = super().get_sending_payload_delta(flow)
        if len(sending_packets_payload_del_len) > 0:
            return format(stats.variation(sending_packets_payload_del_len), self.floating_point_unit)
        return 0
