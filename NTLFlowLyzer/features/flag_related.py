#!/usr/bin/env python3

from ..network_flow_capturer import Flow
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
    def extract(self, flow: Flow) -> int:
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
    def extract(self, flow: Flow) -> int:
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
    def extract(self, flow: Flow) -> int:
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


class FINFlagPercentageInTotal(Feature):
    name = "fin_flag_percentage_in_total"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_packets():
            if packet.has_flagFIN():
                counts += 1
        return float(counts / len(flow.get_packets()))


class PSHFlagPercentageInTotal(Feature):
    name = "psh_flag_percentage_in_total"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_packets():
            if packet.has_flagPSH():
                counts+=1
        return float(counts / len(flow.get_packets()))


class URGFlagPercentageInTotal(Feature):
    name = "urg_flag_percentage_in_total"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_packets():
            if packet.has_flagURG():
                counts+=1
        return float(counts / len(flow.get_packets()))


class ECEFlagPercentageInTotal(Feature):
    name = "ece_flag_percentage_in_total"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_packets():
            if packet.has_flagECE():
                counts+=1
        return float(counts / len(flow.get_packets()))


class SYNFlagPercentageInTotal(Feature):
    name = "syn_flag_percentage_in_total"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_packets():
            if packet.has_flagSYN():
                counts+=1
        return float(counts / len(flow.get_packets()))


class ACKFlagPercentageInTotal(Feature):
    name = "ack_flag_percentage_in_total"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_packets():
            if packet.has_flagACK():
                counts+=1
        return float(counts / len(flow.get_packets()))


class CWRFlagPercentageInTotal(Feature):
    name = "cwr_flag_percentage_in_total"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_packets():
            if packet.has_flagCWR():
                counts+=1
        return float(counts / len(flow.get_packets()))


class RSTFlagPercentageInTotal(Feature):
    name = "rst_flag_percentage_in_total"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_packets():
            if packet.has_flagRST():
                counts+=1
        return float(counts / len(flow.get_packets()))


class FwdFINFlagPercentageInTotal(Feature):
    name = "fwd_fin_flag_percentage_in_total"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_forwardpackets():
            if packet.has_flagFIN():
                counts += 1
        return float(counts / len(flow.get_packets()))


class FwdPSHFlagPercentageInTotal(Feature):
    name = "fwd_psh_flag_percentage_in_total"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_forwardpackets():
            if packet.has_flagPSH():
                counts+=1
        return float(counts / len(flow.get_packets()))


class FwdURGFlagPercentageInTotal(Feature):
    name = "fwd_urg_flag_percentage_in_total"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_forwardpackets():
            if packet.has_flagURG():
                counts+=1
        return float(counts / len(flow.get_packets()))


class FwdECEFlagPercentageInTotal(Feature):
    name = "fwd_ece_flag_percentage_in_total"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_forwardpackets():
            if packet.has_flagECE():
                counts+=1
        return float(counts / len(flow.get_packets()))


class FwdSYNFlagPercentageInTotal(Feature):
    name = "fwd_syn_flag_percentage_in_total"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_forwardpackets():
            if packet.has_flagSYN():
                counts+=1
        return float(counts / len(flow.get_packets()))


class FwdACKFlagPercentageInTotal(Feature):
    name = "fwd_ack_flag_percentage_in_total"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_forwardpackets():
            if packet.has_flagACK():
                counts+=1
        return float(counts / len(flow.get_packets()))


class FwdCWRFlagPercentageInTotal(Feature):
    name = "fwd_cwr_flag_percentage_in_total"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_forwardpackets():
            if packet.has_flagCWR():
                counts+=1
        return float(counts / len(flow.get_packets()))


class FwdRSTFlagPercentageInTotal(Feature):
    name = "fwd_rst_flag_percentage_in_total"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_forwardpackets():
            if packet.has_flagRST():
                counts+=1
        return float(counts / len(flow.get_packets()))


class BwdFINFlagPercentageInTotal(Feature):
    name = "bwd_fin_flag_percentage_in_total"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_backwardpackets():
            if packet.has_flagFIN():
                counts += 1
        return float(counts / len(flow.get_packets()))


class BwdPSHFlagPercentageInTotal(Feature):
    name = "bwd_psh_flag_percentage_in_total"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_backwardpackets():
            if packet.has_flagPSH():
                counts+=1
        return float(counts / len(flow.get_packets()))


class BwdURGFlagPercentageInTotal(Feature):
    name = "bwd_urg_flag_percentage_in_total"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_backwardpackets():
            if packet.has_flagURG():
                counts+=1
        return float(counts / len(flow.get_packets()))


class BwdECEFlagPercentageInTotal(Feature):
    name = "bwd_ece_flag_percentage_in_total"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_backwardpackets():
            if packet.has_flagECE():
                counts+=1
        return float(counts / len(flow.get_packets()))


class BwdSYNFlagPercentageInTotal(Feature):
    name = "bwd_syn_flag_percentage_in_total"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_backwardpackets():
            if packet.has_flagSYN():
                counts+=1
        return float(counts / len(flow.get_packets()))


class BwdACKFlagPercentageInTotal(Feature):
    name = "bwd_ack_flag_percentage_in_total"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_backwardpackets():
            if packet.has_flagACK():
                counts+=1
        return float(counts / len(flow.get_packets()))


class BwdCWRFlagPercentageInTotal(Feature):
    name = "bwd_cwr_flag_percentage_in_total"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_backwardpackets():
            if packet.has_flagCWR():
                counts+=1
        return float(counts / len(flow.get_packets()))


class BwdRSTFlagPercentageInTotal(Feature):
    name = "bwd_rst_flag_percentage_in_total"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_backwardpackets():
            if packet.has_flagRST():
                counts+=1
        return float(counts / len(flow.get_packets()))


class FwdFINFlagPercentageInFwdPackets(Feature):
    name = "fwd_fin_flag_percentage_in_fwd_packets"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_forwardpackets():
            if packet.has_flagFIN():
                counts += 1
        if len(flow.get_forwardpackets()) == 0:
            return 0
        return float(counts / len(flow.get_forwardpackets()))


class FwdPSHFlagPercentageInFwdPackets(Feature):
    name = "fwd_psh_flag_percentage_in_fwd_packets"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_forwardpackets():
            if packet.has_flagPSH():
                counts+=1
        if len(flow.get_forwardpackets()) == 0:
            return 0
        return float(counts / len(flow.get_forwardpackets()))


class FwdURGFlagPercentageInFwdPackets(Feature):
    name = "fwd_urg_flag_percentage_in_fwd_packets"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_forwardpackets():
            if packet.has_flagURG():
                counts+=1
        if len(flow.get_forwardpackets()) == 0:
            return 0
        return float(counts / len(flow.get_forwardpackets()))


class FwdECEFlagPercentageInFwdPackets(Feature):
    name = "fwd_ece_flag_percentage_in_fwd_packets"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_forwardpackets():
            if packet.has_flagECE():
                counts+=1
        if len(flow.get_forwardpackets()) == 0:
            return 0
        return float(counts / len(flow.get_forwardpackets()))


class FwdSYNFlagPercentageInFwdPackets(Feature):
    name = "fwd_syn_flag_percentage_in_fwd_packets"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_forwardpackets():
            if packet.has_flagSYN():
                counts+=1
        if len(flow.get_forwardpackets()) == 0:
            return 0
        return float(counts / len(flow.get_forwardpackets()))


class FwdACKFlagPercentageInFwdPackets(Feature):
    name = "fwd_ack_flag_percentage_in_fwd_packets"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_forwardpackets():
            if packet.has_flagACK():
                counts+=1
        if len(flow.get_forwardpackets()) == 0:
            return 0
        return float(counts / len(flow.get_forwardpackets()))


class FwdCWRFlagPercentageInFwdPackets(Feature):
    name = "fwd_cwr_flag_percentage_in_fwd_packets"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_forwardpackets():
            if packet.has_flagCWR():
                counts+=1
        if len(flow.get_forwardpackets()) == 0:
            return 0
        return float(counts / len(flow.get_forwardpackets()))


class FwdRSTFlagPercentageInFwdPackets(Feature):
    name = "fwd_rst_flag_percentage_in_fwd_packets"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_forwardpackets():
            if packet.has_flagRST():
                counts+=1
        if len(flow.get_forwardpackets()) == 0:
            return 0
        return float(counts / len(flow.get_forwardpackets()))


class BwdFINFlagPercentageInBwdPackets(Feature):
    name = "bwd_fin_flag_percentage_in_bwd_packets"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_backwardpackets():
            if packet.has_flagFIN():
                counts += 1
        if len(flow.get_backwardpackets()) == 0:
            return 0
        return float(counts / len(flow.get_backwardpackets()))


class BwdPSHFlagPercentageInBwdPackets(Feature):
    name = "bwd_psh_flag_percentage_in_bwd_packets"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_backwardpackets():
            if packet.has_flagPSH():
                counts+=1
        if len(flow.get_backwardpackets()) == 0:
            return 0
        return float(counts / len(flow.get_backwardpackets()))


class BwdURGFlagPercentageInBwdPackets(Feature):
    name = "bwd_urg_flag_percentage_in_bwd_packets"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_backwardpackets():
            if packet.has_flagURG():
                counts+=1
        if len(flow.get_backwardpackets()) == 0:
            return 0
        return float(counts / len(flow.get_backwardpackets()))


class BwdECEFlagPercentageInBwdPackets(Feature):
    name = "bwd_ece_flag_percentage_in_bwd_packets"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_backwardpackets():
            if packet.has_flagECE():
                counts+=1
        if len(flow.get_backwardpackets()) == 0:
            return 0
        return float(counts / len(flow.get_backwardpackets()))


class BwdSYNFlagPercentageInBwdPackets(Feature):
    name = "bwd_syn_flag_percentage_in_bwd_packets"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_backwardpackets():
            if packet.has_flagSYN():
                counts+=1
        if len(flow.get_backwardpackets()) == 0:
            return 0
        return float(counts / len(flow.get_backwardpackets()))


class BwdACKFlagPercentageInBwdPackets(Feature):
    name = "bwd_ack_flag_percentage_in_bwd_packets"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_backwardpackets():
            if packet.has_flagACK():
                counts+=1
        if len(flow.get_backwardpackets()) == 0:
            return 0
        return float(counts / len(flow.get_backwardpackets()))


class BwdCWRFlagPercentageInBwdPackets(Feature):
    name = "bwd_cwr_flag_percentage_in_bwd_packets"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_backwardpackets():
            if packet.has_flagCWR():
                counts+=1
        if len(flow.get_backwardpackets()) == 0:
            return 0
        return float(counts / len(flow.get_backwardpackets()))


class BwdRSTFlagPercentageInBwdPackets(Feature):
    name = "bwd_rst_flag_percentage_in_bwd_packets"
    def extract(self, flow: Flow) -> float:
        counts = 0
        for packet in flow.get_backwardpackets():
            if packet.has_flagRST():
                counts+=1
        if len(flow.get_backwardpackets()) == 0:
            return 0
        return float(counts / len(flow.get_backwardpackets()))