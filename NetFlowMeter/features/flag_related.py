from .feature import Feature



##HERE WE USED PACKET AS FEATURES

########################ALL packets #################################
# def fin_flag_counts(packets):
class fin_flag_counts(Feature):
    name = "Flow FIN flag Count"
    def extract(self, packets: object) -> dict:
        counts = 0
        for packet in packets:
            if packet.has_flagFIN():
                counts+=1
        return counts



# def psh_flag_counts(packets):
class psh_flag_counts(Feature):
    name = "Flow PSH flag Count"
    def extract(self, packets: object) -> dict:
        counts = 0
        for packet in packets:
            if packet.has_flagPSH():
                counts+=1
        return counts


# def urg_flag_counts(packets):
class urg_flag_counts(Feature):
    name = "Flow URG flag Count"
    def extract(self, packets: object) -> dict:
        counts = 0
        for packet in packets:
            if packet.has_flagURG():
                counts+=1
        return counts


# def ece_flag_counts(packets):
class ece_flag_counts(Feature):
    name = "Flow ECE flag Count"
    def extract(self,packets: object) -> dict:
        counts = 0
        for packet in packets:
            if packet.has_flagECE():
                counts+=1
        return counts

# def syn_flag_counts(packets):
class syn_flag_counts(Feature):
    name ="Flow ECE flag Count"
    def extract(self, packets: object) -> dict:
        counts = 0
        for packet in packets:
            if packet.has_flagSYN():
                counts+=1
        return counts



# def ack_flag_counts(packets):
class ack_flag_counts(Feature):
    name ="Flow ACK flag Count"
    def extract(self, packets:object) -> dict:
        counts = 0
        for packet in packets:
            if packet.has_flagACK():
                counts+=1
        return counts

# def cwr_flag_counts(packets):
class cwr_flag_counts(Feature):
    name ="Flow CWR flag Count"
    def extract(self, packets: object) -> dict:
        counts = 0
        for packet in packets:
            if packet.has_flagCWR():
                counts+=1
        return counts




# def rst_flag_counts(packets):
class rst_flag_counts(Feature):
    name = "Flow RST flag Count"
    def extract(self, packets: object) -> dict:
        counts = 0
        for packet in packets:
            if packet.has_flagRST():
                counts+=1
        return counts

