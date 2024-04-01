#!/usr/bin/env python3

from ..network_flow_capturer import Flow
from .feature import Feature


class AvgFwdBytesPerBulk(Feature):
    name = "avg_fwd_bytes_per_bulk"
    def extract(self, flow: Flow) -> float:
        if flow.get_fBulkStateCount() != 0:
            return float(flow.get_fBulkSizeTotal() / flow.get_fBulkStateCount())
        return 0


class AvgFwdPacketsPerBulk(Feature):
    name='avg_fwd_packets_per_bulk'
    def extract(self, flow: Flow) -> float:
        if flow.get_fBulkStateCount() != 0:
            return float(flow.get_fBulkPacketCount() / flow.get_fBulkStateCount())
        return 0


class AvgFwdBulkRate(Feature):
    name = "avg_fwd_bulk_rate"
    def extract(self, flow: Flow) -> float:
        if flow.get_fBulkDuration() != 0:
            return float(flow.get_fBulkSizeTotal() / flow.get_fBulkDuration())
        return 0


class AvgBwdBytesPerBulk(Feature):
    name = "avg_bwd_bytes_per_bulk"
    def extract(self, flow: Flow) -> float:
        if flow.bbulkStateCount != 0:
            return float(flow.get_bBulkSizeTotal() / flow.bbulkStateCount)
        return 0


class AvgBwdPacketsPerBulk(Feature):
    name = "avg_bwd_packets_bulk_rate"
    def extract(self, flow: Flow) -> float:
        if flow.get_bBulkStateCount() != 0:
            return float(flow.get_bBulkPacketCount() / flow.get_bBulkStateCount())
        return 0


class AvgBwdBulkRate(Feature):
    name = "avg_bwd_bulk_rate"
    def extract(self, flow: Flow) -> float:
        if flow.get_bBulkDuration() != 0:
            return float(flow.get_bBulkSizeTotal() / flow.get_bBulkDuration())
        return 0


class FwdBulkStateCount(Feature):
    name = "fwd_bulk_state_count"
    def extract(self, flow: Flow) -> float:
        return flow.fbulkStateCount


class FwdBulkSizeTotal(Feature):
    name = "fwd_bulk_total_size"
    def extract(self, flow: Flow) -> float:
        return flow.fbulkSizeTotal


class FwdBulkPacketCount(Feature):
    name = "fwd_bulk_per_packet"
    def extract(self, flow: Flow) -> float:
        return flow.fbulkPacketCount


class FwdBulkDuration(Feature):
    name = "fwd_bulk_duration"
    def extract(self, flow: Flow) -> float:
        return flow.fbulkDuration


class BwdBulkStateCount(Feature):
    name = "bwd_bulk_state_count"
    def extract(self, flow: Flow) -> float:
        return flow.bbulkStateCount


class BwdBulkSizeTotal(Feature):
    name = "bwd_bulk_total_size"
    def extract(self, flow: Flow) -> float:
        return flow.bbulkSizeTotal


class BwdBulkPacketCount(Feature):
    name = "bwd_bulk_per_packet"
    def extract(self, flow: Flow) -> float:
         return flow.bbulkPacketCount


class BwdBulkDuration(Feature):
    name ="bwd_bulk_duration"
    def extract(self, flow: Flow) -> float:
        return flow.bbulkDuration
