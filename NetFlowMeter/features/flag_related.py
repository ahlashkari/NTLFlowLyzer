#### FLAG FUNCTIONS ####
def fin_flag_counts(packets):
    counts = 0
    for packet in packets:
        if packet.has_flagFIN():
            counts+=1
    return counts

def psh_flag_counts(packets):
    counts = 0
    for packet in packets:
        if packet.has_flagPSH():
            counts+=1
    return counts

def urg_flag_counts(packets):
    counts = 0
    for packet in packets:
        if packet.has_flagURG():
            counts+=1
    return counts

def ece_flag_counts(packets):
    counts = 0
    for packet in packets:
        if packet.has_flagECE():
            counts+=1
    return counts

def syn_flag_counts(packets):
    counts = 0
    for packet in packets:
        if packet.has_flagSYN():
            counts+=1
    return counts

def ack_flag_counts(packets):
    counts = 0
    for packet in packets:
        if packet.has_flagACK():
            counts+=1
    return counts

def cwr_flag_counts(packets):
    counts = 0
    for packet in packets:
        if packet.has_flagCWR():
            counts+=1
    return counts

def rst_flag_counts(packets):
    counts = 0
    for packet in packets:
        if packet.has_flagRST():
            counts+=1
    return counts

#
