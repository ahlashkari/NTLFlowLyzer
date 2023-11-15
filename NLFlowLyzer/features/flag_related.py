#!/usr/bin/env python3

from ..net_layer_flow_capturer import Flow
from .feature import Feature


class FINFlagCounts(Feature):
    name = "fin_flag_counts"
    def extract(self, flow: Flow) -> int:
        counts = 0
        for packet in flow.get_packets():
            if packet.has_flagFIN():
                counts+=1
        return counts


class PSHFlagCounts(Feature):
    name = "psh_flag_counts"
    def extract(self, flow: Flow) -> int:
        counts = 0
        for packet in flow.get_packets():
            if packet.has_flagPSH():
                counts+=1
        return counts


class URGFlagCounts(Feature):
    name = "urg_flag_counts"
    def extract(self, flow: Flow) -> int:
        counts = 0
        for packet in flow.get_packets():
            if packet.has_flagURG():
                counts+=1
        return counts


class ECEFlagCounts(Feature):
    name = "ece_flag_counts"
    def extract(self, flow: Flow) -> int:
        counts = 0
        for packet in flow.get_packets():
            if packet.has_flagECE():
                counts+=1
        return counts


class SYNFlagCounts(Feature):
    name = "syn_flag_counts"
    def extract(self, flow: Flow) -> int:
        counts = 0
        for packet in flow.get_packets():
            if packet.has_flagSYN():
                counts+=1
        return counts


class ACKFlagCounts(Feature):
    name = "ack_flag_counts"
    def extract(self, flow:object) -> int:
        counts = 0
        for packet in flow.get_packets():
            if packet.has_flagACK():
                counts+=1
        return counts


class CWRFlagCounts(Feature):
    name = "cwr_flag_counts"
    def extract(self, flow: Flow) -> int:
        counts = 0
        for packet in flow.get_packets():
            if packet.has_flagCWR():
                counts+=1
        return counts


class RSTFlagCounts(Feature):
    name = "rst_flag_counts"
    def extract(self, flow: Flow) -> int:
        counts = 0
        for packet in flow.get_packets():
            if packet.has_flagRST():
                counts+=1
        return counts


class FwdFINFlagCounts(Feature):
    name = "fwd_fin_flag_counts"
    def extract(self, flow: Flow) -> int:
        counts = 0
        for packet in flow.get_forwardpackets():
            if packet.has_flagFIN():
                counts+=1
        return counts


class FwdPSHFlagCounts(Feature):
    name = "fwd_psh_flag_counts"
    def extract(self, flow: Flow) -> int:
        counts = 0
        for packet in flow.get_forwardpackets():
            if packet.has_flagPSH():
                counts+=1
        return counts


class FwdURGFlagCounts(Feature):
    name = "fwd_urg_flag_counts"
    def extract(self, flow: Flow) -> int:
        counts = 0
        for packet in flow.get_forwardpackets():
            if packet.has_flagURG():
                counts+=1
        return counts


class FwdECEFlagCounts(Feature):
    name = "fwd_ece_flag_counts"
    def extract(self, flow: Flow) -> int:
        counts = 0
        for packet in flow.get_forwardpackets():
            if packet.has_flagECE():
                counts+=1
        return counts


class FwdSYNFlagCounts(Feature):
    name = "fwd_syn_flag_counts"
    def extract(self, flow: Flow) -> int:
        counts = 0
        for packet in flow.get_forwardpackets():
            if packet.has_flagSYN():
                counts+=1
        return counts


class FwdACKFlagCounts(Feature):
    name = "fwd_ack_flag_counts"
    def extract(self, flow:object) -> int:
        counts = 0
        for packet in flow.get_forwardpackets():
            if packet.has_flagACK():
                counts+=1
        return counts


class FwdCWRFlagCounts(Feature):
    name = "fwd_cwr_flag_counts"
    def extract(self, flow: Flow) -> int:
        counts = 0
        for packet in flow.get_forwardpackets():
            if packet.has_flagCWR():
                counts+=1
        return counts


class FwdRSTFlagCounts(Feature):
    name = "fwd_rst_flag_counts"
    def extract(self, flow: Flow) -> int:
        counts = 0
        for packet in flow.get_forwardpackets():
            if packet.has_flagRST():
                counts+=1
        return counts


class BwdFINFlagCounts(Feature):
    name = "bwd_fin_flag_counts"
    def extract(self, flow: Flow) -> int:
        counts = 0
        for packet in flow.get_backwardpackets():
            if packet.has_flagFIN():
                counts+=1
        return counts


class BwdPSHFlagCounts(Feature):
    name = "bwd_psh_flag_counts"
    def extract(self, flow: Flow) -> int:
        counts = 0
        for packet in flow.get_backwardpackets():
            if packet.has_flagPSH():
                counts+=1
        return counts


class BwdURGFlagCounts(Feature):
    name = "bwd_urg_flag_counts"
    def extract(self, flow: Flow) -> int:
        counts = 0
        for packet in flow.get_backwardpackets():
            if packet.has_flagURG():
                counts+=1
        return counts


class BwdECEFlagCounts(Feature):
    name = "bwd_ece_flag_counts"
    def extract(self, flow: Flow) -> int:
        counts = 0
        for packet in flow.get_backwardpackets():
            if packet.has_flagECE():
                counts+=1
        return counts


class BwdSYNFlagCounts(Feature):
    name = "bwd_syn_flag_counts"
    def extract(self, flow: Flow) -> int:
        counts = 0
        for packet in flow.get_backwardpackets():
            if packet.has_flagSYN():
                counts+=1
        return counts


class BwdACKFlagCounts(Feature):
    name = "bwd_ack_flag_counts"
    def extract(self, flow:object) -> int:
        counts = 0
        for packet in flow.get_backwardpackets():
            if packet.has_flagACK():
                counts+=1
        return counts


class BwdCWRFlagCounts(Feature):
    name = "bwd_cwr_flag_counts"
    def extract(self, flow: Flow) -> int:
        counts = 0
        for packet in flow.get_backwardpackets():
            if packet.has_flagCWR():
                counts+=1
        return counts


class BwdRSTFlagCounts(Feature):
    name = "bwd_rst_flag_counts"
    def extract(self, flow: Flow) -> int:
        counts = 0
        for packet in flow.get_backwardpackets():
            if packet.has_flagRST():
                counts+=1
        return counts

