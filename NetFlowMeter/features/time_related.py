#!/usr/bin/env python3

import statistics
from ..net_flow_capturer import Flow
from .feature import Feature
from . import utils


class Duration(Feature):
    name = "duration"
    def extract(self, flow: Flow) -> float:
        return utils.calculate_flow_duration(flow)


class ActiveMin(Feature):
    name = "active_min"
    def extract(self, flow: Flow) -> float:
        if not flow.get_flow_active():
            return 0
        return min(flow.get_flow_active())


class ActiveMax(Feature):
    name = "active_max"
    def extract(self, flow: Flow) -> float:
        if not flow.get_flow_active():
            return 0
        return max(flow.get_flow_active())


class ActiveMean(Feature):
    name = "active_mean"
    def extract(self, flow: Flow) -> float:
        if not flow.get_flow_active():
            return 0
        return format(statistics.mean(flow.get_flow_active()), self.floating_point_unit)


class ActiveStd(Feature):
    name = "active_std"
    def extract(self, flow: Flow) -> float:
        if not flow.get_flow_active():
            return 0
        return format(statistics.pstdev(flow.get_flow_active()), self.floating_point_unit)


class IdleMin(Feature):
    name = "idle_min"
    def extract(self, flow: Flow) -> float:
        if not flow.get_flow_idle():
            return 0
        return min(flow.get_flow_idle())


class IdleMax(Feature):
    name = "idle_max"
    def extract(self, flow: Flow) -> float:
        if not flow.get_flow_idle():
            return 0
        return max(flow.get_flow_idle())


class IdleMean(Feature):
    name = "idle_mean"
    def extract(self, flow: Flow) -> float:
        if not flow.get_flow_idle():
            return 0
        return format(statistics.mean(flow.get_flow_idle()), self.floating_point_unit)


class IdleStd(Feature):
    name = "idle_std"
    def extract(self, flow: Flow) -> float:
        if not flow.get_flow_idle():
            return 0
        return format(statistics.pstdev(flow.get_flow_idle()), self.floating_point_unit)