import numpy as np


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
            
###############################

def flow_duration(flow):
    return flow.get_flow_last_seen() - flow.get_flow_start_time()

###############################
#### PACKET COUNT ####
def packet_count(packets):
    return len(packets)

def flow_packets_per_second(flow):
    try:
        return len(flow.get_packets())/float(flow_duration(flow))
    except ZeroDivisionError:
        return 0

def bflow_packets_per_second(flow):
    try:
        return len(flow.get_backwardpackets())/float(flow_duration(flow))
    except ZeroDivisionError:
            return 0

def fflow_packets_per_second(flow):
    try:
        return len(flow.get_forwardpackets())/float(flow_duration(flow))
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
#################################

