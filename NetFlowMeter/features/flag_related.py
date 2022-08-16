from .feature import Feature


class FINFlagCounts(Feature):
    name = "fin_flag_counts"
    def extract(self, flow: object) -> dict:
        counts = 0
        for packet in flow.get_packets():
            if packet.has_flagFIN():
                counts+=1
        return counts


class PSHFlagCounts(Feature):
    name = "psh_flag_counts"
    def extract(self, flow: object) -> dict:
        counts = 0
        for packet in flow.get_packets():
            if packet.has_flagPSH():
                counts+=1
        return counts


class URGFlagCounts(Feature):
    name = "urg_flag_counts"
    def extract(self, flow: object) -> dict:
        counts = 0
        for packet in flow.get_packets():
            if packet.has_flagURG():
                counts+=1
        return counts


class ECEFlagCounts(Feature):
    name = "ece_flag_counts"
    def extract(self, flow: object) -> dict:
        counts = 0
        for packet in flow.get_packets():
            if packet.has_flagECE():
                counts+=1
        return counts


class SYNFlagCounts(Feature):
    name = "syn_flag_counts"
    def extract(self, flow: object) -> dict:
        counts = 0
        for packet in flow.get_packets():
            if packet.has_flagSYN():
                counts+=1
        return counts


class ACKFlagCounts(Feature):
    name = "ack_flag_counts"
    def extract(self, flow:object) -> dict:
        counts = 0
        for packet in flow.get_packets():
            if packet.has_flagACK():
                counts+=1
        return counts


class CWRFlagCounts(Feature):
    name = "cwr_flag_counts"
    def extract(self, flow: object) -> dict:
        counts = 0
        for packet in flow.get_packets():
            if packet.has_flagCWR():
                counts+=1
        return counts


class RSTFlagCounts(Feature):
    name = "rst_flag_counts"
    def extract(self, flow: object) -> dict:
        counts = 0
        for packet in flow.get_packets():
            if packet.has_flagRST():
                counts+=1
        return counts
