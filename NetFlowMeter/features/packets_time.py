#!/usr/bin/env python3

import statistics
from scipy import stats
from .feature import Feature


class Duration(Feature):
    name = "duration"
    def extract(self, flow: object) -> float:
        return format(flow.get_flow_last_seen() - flow.get_flow_start_time(), self.floating_point_unit)


class ActiveMin(Feature):
    name = "active_min"
    def extract(self, flow: object) -> float:
        if not flow.get_flow_active():
            return 0
        return min(flow.get_flow_active())


class ActiveMax(Feature):
    name = "active_max"
    def extract(self, flow: object) -> float:
        if not flow.get_flow_active():
            return 0
        return max(flow.get_flow_active())


class ActiveMean(Feature):
    name = "active_mean"
    def extract(self, flow: object) -> float:
        if not flow.get_flow_active():
            return 0
        return np.mean(flow.get_flow_active())


class ActiveStd(Feature):
    name = "active_std"
    def extract(self, flow: object) -> float:
        if not flow.get_flow_active():
            return 0
        return np.std(flow.get_flow_active())


class IdleMin(Feature):
    name = "idle_min"
    def extract(self, flow: object) -> float:
        if not flow.get_flow_idle():
            return 0
        return min(flow.get_flow_idle())


class IdleMax(Feature):
    name = "idle_max"
    def extract(self, flow: object) -> float:
        if not flow.get_flow_idle():
            return 0
        return max(flow.get_flow_idle())


class IdleMean(Feature):
    name = "idle_mean"
    def extract(self, flow: object) -> float:
        if not flow.get_flow_idle():
            return 0
        return np.mean(flow.get_flow_idle())


class IdleStd(Feature):
    name = "idle_std"
    def extract(self, flow: object) -> float:
        if not flow.get_flow_idle():
            return 0
        return np.std(flow.get_flow_idle())
