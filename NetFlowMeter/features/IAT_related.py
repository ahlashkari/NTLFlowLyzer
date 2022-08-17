import numpy as np

from .feature import Feature
from . import utils


class IAT(Feature):
    name = "IAT"
    def extract(self, flow: object) -> dict:
        return utils.calculate_IAT(flow.get_packets())


class PacketsIATMean(Feature):
    name = "packets_IAT_mean"
    def extract(self, flow: object) -> dict:
        times = utils.calculate_IAT(flow.get_packets())
        if times:
            return np.mean(times)
        return 0


class PacketsIATStd(Feature):
    name = "packet_IAT_Std"
    def extract(self, flow: object) -> dict:
        times = utils.calculate_IAT(flow.get_packets())
        try:
            return np.std(times)
        except RuntimeWarning:
            return 0
        except ZeroDivisionError:
            return 0
        except ValueError:
            return 0


class PacketsIATMax(Feature):
    name = "packet_IAT_max"
    def extract(self, flow: object) -> dict:
        times = utils.calculate_IAT(flow.get_packets())
        if times:
            return max(times)
        return 0


class PacketsIATMin(Feature):
    name = "packet_IAT_min"
    def extract(self, flow: object) -> dict:
        times = utils.calculate_IAT(flow.get_packets())
        if times:
            return min(times)
        return 0


class PacketsIATSum(Feature):
    name = "packet_IAT_Total"
    def extract(self, flow: object) -> dict:
        times = utils.calculate_IAT(flow.get_packets())
        if times:
            return sum(times)
        return 0


class FwdIAT(Feature):
    name = "fwd_IAT"
    def extract(self, flow: object) -> dict:
        return utils.calculate_IAT(flow.get_forwardpackets())


class FwdPacketsIATMean(Feature):
    name = "fwd_packets_IAT_mean"
    def extract(self, flow: object) -> dict:
        times = utils.calculate_IAT(flow.get_forwardpackets())
        if times:
            return np.mean(times)
        return 0


class FwdPacketsIATStd(Feature):
    name = "fwd_packets_IAT_Std"
    def extract(self, flow: object) -> dict:
        times = utils.calculate_IAT(flow.get_forwardpackets())
        try:
            return np.std(times)
        except RuntimeWarning:
            return 0
        except ZeroDivisionError:
            return 0
        except ValueError:
            return 0


class FwdPacketsIATMax(Feature):
    name = "fwd_packets_IAT_max"
    def extract(self, flow: object) -> dict:
        times = utils.calculate_IAT(flow.get_forwardpackets())
        if times:
            return max(times)
        return 0


class FwdPacketsIATMin(Feature):
    name = "fwd_packets_IAT_min"
    def extract(self, flow: object) -> dict:
        times = utils.calculate_IAT(flow.get_forwardpackets())
        if times:
            return min(times)
        return 0


class FwdPacketsIATSum(Feature):
    name = "fwd_packets_IAT_Total"
    def extract(self, flow: object) -> dict:
        times = utils.calculate_IAT(flow.get_forwardpackets())
        if times:
            return sum(times)
        return 0


class BwdIAT(Feature):
    name = "bwd_IAT"
    def extract(self, flow: object) -> dict:
        return utils.calculate_IAT(flow.get_backwardpackets())


class BwdPacketsIATMean(Feature):
    name = "bwd_packets_IAT_mean"
    def extract(self, flow: object) -> dict:
        times = utils.calculate_IAT(flow.get_backwardpackets())
        if times:
            return np.mean(times)
        return 0


class BwdPacketsIATStd(Feature):
    name = "bwd_packets_IAT_Std"
    def extract(self, flow: object) -> dict:
        times = utils.calculate_IAT(flow.get_backwardpackets())
        try:
            return np.std(times)
        except RuntimeWarning:
            return 0
        except ZeroDivisionError:
            return 0
        except ValueError:
            return 0


class BwdPacketsIATMax(Feature):
    name = "bwd_packets_IAT_max"
    def extract(self, flow: object) -> dict:
        times = utils.calculate_IAT(flow.get_backwardpackets())
        if times:
            return max(times)
        return 0


class BwdPacketsIATMin(Feature):
    name = "bwd_packets_IAT_min"
    def extract(self, flow: object) -> dict:
        times = utils.calculate_IAT(flow.get_backwardpackets())
        if times:
            return min(times)
        return 0


class BwdPacketsIATSum(Feature):
    name = "bwd_packets_IAT_Total"
    def extract(self, flow: object) -> dict:
        times = utils.calculate_IAT(flow.get_backwardpackets())
        if times:
            return sum(times)
        return 0
