import numpy as np


#### FLAG FUNCTIONS ####
def fin_flag_counts(packets):
    counts = 0
    for packet in packets:
        if packet.has_flagFIN():
            counts += 1
    return counts


def psh_flag_counts(packets):
    counts = 0
    for packet in packets:
        if packet.has_flagPSH():
            counts += 1
    return counts


def urg_flag_counts(packets):
    counts = 0
    for packet in packets:
        if packet.has_flagURG():
            counts += 1
    return counts


def ece_flag_counts(packets):
    counts = 0
    for packet in packets:
        if packet.has_flagECE():
            counts += 1
    return counts


def syn_flag_counts(packets):
    counts = 0
    for packet in packets:
        if packet.has_flagSYN():
            counts += 1
    return counts


def ack_flag_counts(packets):
    counts = 0
    for packet in packets:
        if packet.has_flagACK():
            counts += 1
    return counts


def cwr_flag_counts(packets):
    counts = 0
    for packet in packets:
        if packet.has_flagCWR():
            counts += 1
    return counts


def rst_flag_counts(packets):
    counts = 0
    for packet in packets:
        if packet.has_flagRST():
            counts += 1
    return counts


###############################

def flow_duration(flow):
    return flow.get_flow_last_seen() - flow.get_flow_start_time()


###############################
#### PACKET COUNT ####
def packet_count(packets):
    return len(packets)


def flow_packets_per_second(flow):
    try:
        return len(flow.get_packets()) / float(flow_duration(flow))
    except ZeroDivisionError:
        return 0


def bflow_packets_per_second(flow):
    try:
        return len(flow.get_backwardpackets()) / float(flow_duration(flow))
    except ZeroDivisionError:
        return 0


def fflow_packets_per_second(flow):
    try:
        return len(flow.get_forwardpackets()) / float(flow_duration(flow))
    except ZeroDivisionError:
        return 0


###############################

#### PACKET LENGTH ####
def flow_packets_length_max(packets):
    packets_len = [packet.get_length() for packet in packets]
    if packets_len:
        return max(packets_len)
    return 0


def flow_packets_length_min(packets):
    packets_len = [packet.get_length() for packet in packets]
    if packets_len:
        return min(packets_len)
    return 0


def flow_packets_length_mean(packets):
    packets_len = [packet.get_length() for packet in packets]
    if packets_len:
        return np.mean(packets_len)
    return 0


def flow_packets_length_sum(packets):
    packets_len = [packet.get_length() for packet in packets]
    if packets_len:
        return sum(packets_len)
    return 0


def flow_packets_length_std(packets):
    packets_len = [packet.get_length() for packet in packets]
    if packets_len:
        return np.std(packets_len)
    return 0


##################################
####IAT######

def IAT(packets):  # the code should be improved
    times = [packet.get_timestamp() for packet in packets]
    for i in range(len(times) - 1):
        times[i] = times[i + 1] - times[i]
    if len(times) == 0:
        pass
    else:
        times.pop()
    return times


def flow_packets_IAT_mean(packets):
    times = IAT(packets)
    if len(times) == 0:
        return 0
    else:
        return np.mean(times)


def flow_packets_IAT_std(packets):  # should be developed for NaN value
    times = IAT(packets)
    try:
        return np.std(times)
    except RuntimeWarning:
        return None
    except ZeroDivisionError:
        return 0
    except ValueError:
        return 0


def flow_packets_IAT_max(packets):
    times = IAT(packets)
    try:
        return np.max(times)
    except ValueError:
        pass


def flow_packets_IAT_min(packets):
    times = IAT(packets)
    try:
        return np.min(times)
    except ValueError:
        pass


def flow_packets_IAT_sum(packets):
    times = IAT(packets)
    return sum(times)


##forward packets IAT ##
def flow_fwdpackets_IAT_mean(flow):
    fwdPackets = flow.get_forwardpackets()
    times = IAT(fwdPackets)
    if len(times) == 0:
        return 0
    else:
        return np.mean(times)


def flow_fwdpackets_IAT_std(flow):
    fwdPackets = flow.get_forwardpackets()
    times = IAT(fwdPackets)
    try:
        return np.std(times)
    except RuntimeWarning:
        return None
    except ZeroDivisionError:
        return None
    except ValueError:
        return None


def flow_fwdpackets_IAT_max(flow):
    fwdPackets = flow.get_forwardpackets()
    times = IAT(fwdPackets)
    try:
        return np.max(times)
    except ValueError:
        return None


def flow_fwdpackets_IAT_min(flow):
    fwdPackets = flow.get_forwardpackets()
    times = IAT(fwdPackets)
    try:
        return np.min(times)
    except ValueError:
        return None


def flow_fwdpackets_IAT_sum(flow):
    fwdPackets = flow.get_forwardpackets()
    times = IAT(fwdPackets)
    return sum(times)


##backward packets IAT##
def flow_bwdpackets_IAT_mean(flow):
    bwdPackets = flow.get_backwardpackets()
    times = IAT(bwdPackets)
    if len(times) == 0:
        return 0
    else:
        return np.mean(times)


def flow_bwdpackets_IAT_std(flow):
    bwdPackets = flow.get_backwardpackets()
    times = IAT(bwdPackets)
    try:
        return np.std(times)
    except RuntimeWarning:
        return None
    except ZeroDivisionError:
        return None
    except ValueError:
        return None


def flow_bwdpackets_IAT_max(flow):
    bwdPackets = flow.get_backwardpackets()
    times = IAT(bwdPackets)
    try:
        return np.max(times)
    except ValueError:
        return None


def flow_bwdpackets_IAT_min(flow):
    bwdPackets = flow.get_backwardpackets()
    times = IAT(bwdPackets)
    try:
        return np.min(times)
    except ValueError:
        return None


def flow_bwdpackets_IAT_sum(flow):
    bwdPackets = flow.get_backwardpackets()
    times = IAT(bwdPackets)
    return sum(times)

#################################



