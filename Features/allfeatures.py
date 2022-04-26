#Raw functions- will be classified later

import statistics
from statistics import *


def statistics(input_list):
    output_dict = {}
    output_dict['sum'] = sum(input_list)
    output_dict['min'] = min(input_list)
    output_dict['max'] = max(input_list)
    output_dict['mean'] = mean(input_list)
    output_dict['std'] = stdev(input_list)
    return output_dict


def flag_counts(flow, flag_name):
    flag_counts = {}
    for packet in flow.get_packets():
        if packet.has_flagFIN:
            flag_counts['FIN']+=1
        elif packet.has_flagPSH:
            flag_counts['FIN']+=1
        elif packet.has_flagURG:
            flag_counts['URG']+=1
        elif packet.has_flagECE:
            flag_counts['ECE']+=1
        elif packet.has_flagSYN:
            flag_counts['SYN']+=1
        elif packet.has_flagACK:
            flag_counts['ACK']+=1
        elif packet.has_flagCWR:
            flag_counts['CWR']+=1
        elif packet.has_flagRST:
            flag_counts['RST']+=1
    return flag_counts[flag_name]


def flow_packets_length_statistics(flow):
    plen_stats = {}
    packets_len = [len(packet) for packet in flow.get_packets()]
    return statistics(packets_len)

def fwdflow_packets_length_statistics(flow, operation):
    plen_stats = {}
    packets_len = [len(packet) for packet in flow.get_forwardpackets()]
    return statistics(packets_len)

def bwdflow_packets_length_statistics(flow, operation):
    plen_stats = {}
    packets_len = [len(packet) for packet in flow.get_backwardpackets()]
    return statistics(packets_len)

def flow_duration(flow):
    return flow.get_flow_last_seen() - flow.get_flow_start_time()
    
def totalfwdpackets(flow):
    return len(flow.get_forwardpackets())

def totalbwdpackets(flow):
    return len(flow.get_forwardpackets())

def IAT(packets):
    times = [p.get_timestamp() for p in packets]
    for i in range(len(times)-1):
        times[i] = times[i+1] - times[i]
    times.pop()
    return times

def flow_IAT_statistics(flow):
    times = IAT(flow.get_packets())
    return statistics(times)

def fwdflow_IAT_statistics(flow):
    times = IAT(flow.get_forwardpackets())
    return statistics(times)

def flow_IAT_statistics(flow):
    times = IAT(flow.get_forwardpackets())
    return statistics(times)
    
        
    
    
    
                              
               
    
    
