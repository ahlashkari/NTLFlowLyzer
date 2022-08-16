import numpy as np

from .feature import Feature
from . import utils


class IAT(Feature):
    name = "IAT"
    def extract(self, flow: object) -> dict:
        return utils.calculate_IAT(flow)


class PacketsIATMean(Feature):
    name = "packets_IAT_mean"
    def extract(self, flow: object) -> dict:
        times = utils.calculate_IAT(flow)
        if times:
            return np.mean(times)
        return 0


class PacketsIATStd(Feature):
    name = "packet_IAT_Std"
    def extract(self, flow: object) -> dict:
        times = utils.calculate_IAT(flow)
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
        times = utils.calculate_IAT(flow)
        if times:
            return max(times)
        return 0


class PacketsIATMin(Feature):
    name = "packet_IAT_min"
    def extract(self, flow: object) -> dict:
        times = utils.calculate_IAT(flow)
        if times:
            return min(times)
        return 0


class PacketsIATSum(Feature):
    name = "packet_IAT_Total"
    def extract(self, flow: object) -> dict:
        times = utils.calculate_IAT(flow)
        if times:
            return sum(times)
        return 0
