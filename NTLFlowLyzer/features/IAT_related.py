#!/usr/bin/env python3

import statistics

from scipy import stats
from .feature import Feature
from ..network_flow_capturer import Flow
from . import utils


class PacketsIATMean(Feature):
    name = "packets_IAT_mean"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_packets())
        if times:
            return format(statistics.mean(times), self.floating_point_unit)
        return 0


class PacketsIATStd(Feature):
    name = "packet_IAT_std"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_packets())
        try:
            return format(statistics.pstdev(times), self.floating_point_unit)
        except (ZeroDivisionError, ValueError):
            return 0


class PacketsIATMax(Feature):
    name = "packet_IAT_max"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_packets())
        if times:
            return max(times)
        return 0


class PacketsIATMin(Feature):
    name = "packet_IAT_min"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_packets())
        if times:
            return min(times)
        return 0


class PacketsIATSum(Feature):
    name = "packet_IAT_total"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_packets())
        if times:
            return sum(times)
        return 0


class PacketsIATMedian(Feature):
    name = "packets_IAT_median"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_packets())
        try:
            return format(statistics.median(times), self.floating_point_unit)
        except (ZeroDivisionError, ValueError):
            return 0


class PacketsIATSkewness(Feature):
    name = "packets_IAT_skewness"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_packets())
        try:
            return format(float(stats.skew(times)), self.floating_point_unit)
        except (ZeroDivisionError, ValueError):
            return 0


class PacketsIATCoV(Feature):
    name = "packets_IAT_cov"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_packets())
        try:
            return format(stats.variation(times), self.floating_point_unit)
        except (ZeroDivisionError, ValueError):
            return 0


class PacketsIATMode(Feature):
    name = "packets_IAT_mode"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_packets())
        try:
            if len(times) > 0:
                return format(float(stats.mode(times)[0]), self.floating_point_unit)
            return 0
        except (ZeroDivisionError, ValueError):
            return 0


class PacketsIATVariance(Feature):
    name = "packets_IAT_variance"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_packets())
        try:
            return format(statistics.pvariance(times), self.floating_point_unit)
        except (ZeroDivisionError, ValueError):
            return 0


class FwdPacketsIATMean(Feature):
    name = "fwd_packets_IAT_mean"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_forwardpackets())
        if times:
            return format(statistics.mean(times), self.floating_point_unit)
        return 0


class FwdPacketsIATStd(Feature):
    name = "fwd_packets_IAT_std"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_forwardpackets())
        try:
            return format(statistics.pstdev(times), self.floating_point_unit)
        except (ZeroDivisionError, ValueError):
            return 0


class FwdPacketsIATMax(Feature):
    name = "fwd_packets_IAT_max"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_forwardpackets())
        if times:
            return max(times)
        return 0


class FwdPacketsIATMin(Feature):
    name = "fwd_packets_IAT_min"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_forwardpackets())
        if times:
            return min(times)
        return 0


class FwdPacketsIATSum(Feature):
    name = "fwd_packets_IAT_total"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_forwardpackets())
        if times:
            return sum(times)
        return 0


class FwdPacketsIATMedian(Feature):
    name = "fwd_packets_IAT_median"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_forwardpackets())
        try:
            return format(statistics.median(times), self.floating_point_unit)
        except (ZeroDivisionError, ValueError):
            return 0


class FwdPacketsIATSkewness(Feature):
    name = "fwd_packets_IAT_skewness"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_forwardpackets())
        try:
            return format(float(stats.skew(times)), self.floating_point_unit)
        except (ZeroDivisionError, ValueError):
            return 0


class FwdPacketsIATCoV(Feature):
    name = "fwd_packets_IAT_cov"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_forwardpackets())
        try:
            return format(stats.variation(times), self.floating_point_unit)
        except (ZeroDivisionError, ValueError):
            return 0


class FwdPacketsIATMode(Feature):
    name = "fwd_packets_IAT_mode"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_forwardpackets())
        try:
            if len(times) > 0:
                return format(float(stats.mode(times)[0]), self.floating_point_unit)
            return 0
        except (ZeroDivisionError, ValueError):
            return 0


class FwdPacketsIATVariance(Feature):
    name = "fwd_packets_IAT_variance"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_forwardpackets())
        try:
            return format(statistics.pvariance(times), self.floating_point_unit)
        except (ZeroDivisionError, ValueError):
            return 0


class BwdPacketsIATMean(Feature):
    name = "bwd_packets_IAT_mean"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_backwardpackets())
        if times:
            return format(statistics.mean(times), self.floating_point_unit)
        return 0


class BwdPacketsIATStd(Feature):
    name = "bwd_packets_IAT_std"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_backwardpackets())
        try:
            return format(statistics.pstdev(times), self.floating_point_unit)
        except (ZeroDivisionError, ValueError):
            return 0


class BwdPacketsIATMax(Feature):
    name = "bwd_packets_IAT_max"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_backwardpackets())
        if times:
            return max(times)
        return 0


class BwdPacketsIATMin(Feature):
    name = "bwd_packets_IAT_min"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_backwardpackets())
        if times:
            return min(times)
        return 0


class BwdPacketsIATSum(Feature):
    name = "bwd_packets_IAT_total"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_backwardpackets())
        if times:
            return sum(times)
        return 0


class BwdPacketsIATMedian(Feature):
    name = "bwd_packets_IAT_median"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_backwardpackets())
        try:
            return format(statistics.median(times), self.floating_point_unit)
        except (ZeroDivisionError, ValueError):
            return 0


class BwdPacketsIATSkewness(Feature):
    name = "bwd_packets_IAT_skewness"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_backwardpackets())
        try:
            return format(float(stats.skew(times)), self.floating_point_unit)
        except (ZeroDivisionError, ValueError):
            return 0


class BwdPacketsIATCoV(Feature):
    name = "bwd_packets_IAT_cov"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_backwardpackets())
        try:
            return format(stats.variation(times), self.floating_point_unit)
        except (ZeroDivisionError, ValueError):
            return 0


class BwdPacketsIATMode(Feature):
    name = "bwd_packets_IAT_mode"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_backwardpackets())
        try:
            if len(times) > 0:
                return format(float(stats.mode(times)[0]), self.floating_point_unit)
            return 0
        except (ZeroDivisionError, ValueError):
            return 0


class BwdPacketsIATVariance(Feature):
    name = "bwd_packets_IAT_variance"
    def extract(self, flow: Flow) -> float:
        times = utils.calculate_IAT(flow.get_backwardpackets())
        try:
            return format(statistics.pvariance(times), self.floating_point_unit)
        except (ZeroDivisionError, ValueError):
            return 0