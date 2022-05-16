#!/usr/bin/env python
# coding: utf-8

# In[104]:


import scapy
from scapy.all import *

from scipy.special import logsumexp
# In[105]:


import pandas as pd


# In[106]:


import numpy as np
import statistics

from Reader import flow
from Reader.flow import Flow
# In[107]:


class Packet():
    
    def __init__(self, src_ip=" ", src_port=0, dst_ip=" ", dst_port=0, protocol=0, flags="", timestamp=0, forward=True , length=0):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.flags = flags
        self.timestamp = timestamp
        self.forward = forward
        self.length = length
        
    def get_src_ip(self):
        return self.src_ip

    def get_dst_ip(self):
        return self.dst_ip

    def get_src_port(self):
        return self.src_port

    def get_dst_port(self):
        return self.dst_port
    
    def get_protocol(self):
        return self.protocol
    
    def has_flagFIN(self): 
        return 'F' in self.flags
    
    def has_flagPSH(self):
        return 'P' in self.flags

    def has_flagURG(self):
        return 'U' in self.flags
    
    def has_flagECE(self):
        return 'E' in self.flags
    
    def has_flagSYN(self):
        return 'S' in self.flags
    
    def has_flagACK(self):
        return 'A' in self.flags

    def has_flagCWR(self):
        return 'C' in self.flags
    
    def has_flagRST(self):
        return 'R' in self.flags
    
    def is_forward(self):
        return self.forward
    
    def get_timestamp(self):
        return self.timestamp
    
    def get_length(self):
        return self.length


# In[108]:


class Flow(object):
    
    def __init__(self, first_packet):
        self.src_ip = first_packet.get_src_ip()
        self.dst_ip = first_packet.get_dst_ip()
        self.src_port = first_packet.get_src_port()
        self.dst_port = first_packet.get_dst_port()
        self.protocol = first_packet.get_protocol()
        self.first_packet = first_packet
        self.flow_start_time = first_packet.get_timestamp()
        self.packets = []
        self.flow_id = str(self.src_ip) + "-" + str(self.src_port) + "-" + str(self.dst_ip) + "-" + str(self.dst_port) + "-" + str(self.protocol)
        #self.forwardpackets = []  ##building the forward/backward from the reader##
        #self.backwardpackets = []

    def add_packet(self, packet) -> None:
        self.packets.append(packet)

    def get_src_ip(self):
        return self.src_ip

    def get_dst_ip(self):
        return self.dst_ip

    def get_src_port(self):
        return self.src_port

    def get_dst_port(self):
        return self.dst_port
    
    def get_protocol(self):
        return self.protocol

    def get_packets(self):
        return self.packets
    
    def get_flow_start_time(self):
        return self.flow_start_time
    
    def get_flow_last_seen(self):
        return self.packets[-1].get_timestamp()
    
    #def get_forwardpackets(self):
        #return self.forwardpackets
    
    #def get_backwardpackets(self):
        #return self.backwardpackets
        
    def get_forwardpackets(self):
        return [p for p in self.packets if p.is_forward() == True]
    
    def get_backwardpackets(self):
        return [p for p in self.packets if p.is_forward() == False]
    
    def get_flow_id(self):
        return self.flow_id
        


# In[109]:


class flow_capturer:
    
    def __init__(self):
        self.finished_flows = []
        self.current_flows = []
        self.all_flows = []
        
    def capture(self, pcap_file):
        packets = rdpcap(pcap_file)
        for pkt in packets: ## Do we check other protocols?
            if TCP in pkt:
                packet = Packet(src_ip=pkt[IP].src, src_port=pkt[TCP].sport, dst_ip=pkt[IP].dst,
                                dst_port=pkt[TCP].dport, protocol=pkt[IP].proto,
                                flags=str(pkt[TCP].flags), timestamp=pkt.time, length= len(pkt))
            
                self.__add_packet_to_flow(packet)
        self.all_flows = self.finished_flows + self.current_flows
        return self.all_flows
    
    def __add_packet_to_flow(self, packet):
        flow = self.__search_for_flow(packet)
        if flow == None:
            self.__create_new_flow(packet)
        else:
            flow.add_packet(packet)
            if packet.has_flagFIN() == True: ##add the other constraints
                self.finished_flows.append(flow)
                self.current_flows.remove(flow)


    def __search_for_flow(self, packet) -> object:
        for flow in self.current_flows:
            if (flow.get_src_ip() == packet.get_src_ip() or flow.get_src_ip() == packet.get_dst_ip()) and (flow.get_dst_ip() == packet.get_src_ip() or flow.get_dst_ip() == packet.get_dst_ip()) and                (flow.get_src_port() == packet.get_src_port() or flow.get_src_port() == packet.get_dst_port()) and                (flow.get_dst_port() == packet.get_src_port() or flow.get_dst_port() == packet.get_dst_port()):
                
                if flow.get_src_ip() == packet.get_dst_ip():
                    packet.forward=False
                    
                return flow

        return None

    def __create_new_flow(self, packet) -> None:
        new_flow = Flow(packet)
        new_flow.add_packet(packet)
        self.current_flows.append(new_flow)


# In[110]:


#capturing flows

capturer = flow_capturer()
flows = capturer.capture("data.pcap")


# In[148]:


#write the feature functions here

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


##################################
####IAT######

def IAT(packets):  #the code should be improved
    times = [packet.get_timestamp() for packet in packets]
    for i in range(len(times)-1):
        times[i] = times[i+1] - times[i]
    if len(times)==0:
        pass
    else:
        times.pop()
    return times

def flow_packets_IAT_mean(packets):
    times=IAT(packets)
    if len(times)==0:
        return 0
    else:
        return np.mean(times)


def flow_packets_IAT_std(packets): # should be developed for NaN value
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
    fwdPackets= flow.get_forwardpackets()
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
    return  sum(times)

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
        return  None


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
    return  sum(times)

#################################





class csv_writer:
        
    def create_csv(self, flows_list):
        flows_dict = {}
        cnt = 0
        #each flow:
        for flow in flows_list:
            
            packets = flow.get_packets()
            bpackets = flow.get_backwardpackets()
            fpackets = flow.get_forwardpackets()
            
            flows_dict[cnt]={}
            #flow identifications
            flows_dict[cnt]['Flow Id'] = flow.get_flow_id()
            flows_dict[cnt]['Source IP'] = flow.get_src_ip()
            flows_dict[cnt]['Source Port'] = flow.get_src_port()
            flows_dict[cnt]['Destination IP'] = flow.get_dst_ip()
            flows_dict[cnt]['Destination Port'] = flow.get_dst_port()
            flows_dict[cnt]['Protocol'] = flow.get_protocol()
            #flags ##flow
            flows_dict[cnt]['Flow # FIN'] = fin_flag_counts(packets)
            flows_dict[cnt]['Flow # PSH'] = psh_flag_counts(packets)
            flows_dict[cnt]['Flow # URG'] = urg_flag_counts(packets)
            flows_dict[cnt]['Flow # ECE'] = ece_flag_counts(packets)
            flows_dict[cnt]['Flow # SYN'] = syn_flag_counts(packets)
            flows_dict[cnt]['Flow # ACK'] = ack_flag_counts(packets)
            flows_dict[cnt]['Flow # CWR'] = cwr_flag_counts(packets)
            flows_dict[cnt]['Flow # RST'] = rst_flag_counts(packets)
            #flags ##bflow
            flows_dict[cnt]['Bflow # FIN'] = fin_flag_counts(bpackets)
            flows_dict[cnt]['Bflow # PSH'] = psh_flag_counts(bpackets)
            flows_dict[cnt]['Bflow # URG'] = urg_flag_counts(bpackets)
            flows_dict[cnt]['Bflow # ECE'] = ece_flag_counts(bpackets)
            flows_dict[cnt]['Bflow # SYN'] = syn_flag_counts(bpackets)
            flows_dict[cnt]['Bflow # ACK'] = ack_flag_counts(bpackets)
            flows_dict[cnt]['Bflow # CWR'] = cwr_flag_counts(bpackets)
            flows_dict[cnt]['Bflow # RST'] = rst_flag_counts(bpackets)
            #flags ##fflow
            flows_dict[cnt]['Fflow # FIN'] = fin_flag_counts(fpackets)
            flows_dict[cnt]['Fflow # PSH'] = psh_flag_counts(fpackets)
            flows_dict[cnt]['Fflow # URG'] = urg_flag_counts(fpackets)
            flows_dict[cnt]['Fflow # ECE'] = ece_flag_counts(fpackets)
            flows_dict[cnt]['Fflow # SYN'] = syn_flag_counts(fpackets)
            flows_dict[cnt]['Fflow # ACK'] = ack_flag_counts(fpackets)
            flows_dict[cnt]['Fflow # CWR'] = cwr_flag_counts(fpackets)
            flows_dict[cnt]['Fflow # RST'] = rst_flag_counts(fpackets)
            #time
            flows_dict[cnt]['Flow Duration'] = flow_duration(flow)
            #packet counts ##flow
            flows_dict[cnt]['Flow # Packets'] = packet_count(packets)
            flows_dict[cnt]['Flow # Packets Per Second'] = flow_packets_per_second(flow)
            #packet counts ##bflow
            flows_dict[cnt]['BFlow # Packets'] = packet_count(bpackets)
            flows_dict[cnt]['Bflow # Packets Per Second'] = bflow_packets_per_second(flow)
            #packet counts ##fflow
            flows_dict[cnt]['Fflow # packets'] = packet_count(fpackets)
            flows_dict[cnt]['Fflow # Packets Per Second'] = fflow_packets_per_second(flow)
            #packet length ##flow
            flows_dict[cnt]['Flow Packet Lenght Max'] = flow_packets_length_max(packets)
            flows_dict[cnt]['Flow Packet Lenght Min'] = flow_packets_length_min(packets)
            flows_dict[cnt]['Flow Packet Lenght Mean'] = flow_packets_length_mean(packets)
            flows_dict[cnt]['Flow Packet Lenght Sum'] = flow_packets_length_sum(packets)
            flows_dict[cnt]['Flow Packet Lenght Std'] = flow_packets_length_std(packets)

            #IAT features## packets#
            flows_dict[cnt]['Flow packet IAT mean'] = flow_packets_IAT_mean(packets)  #should be improved
            flows_dict[cnt]['Flow packet IAT std'] = flow_packets_IAT_std(packets)#should be improved
            flows_dict[cnt]['Flow packet IAT max'] = flow_packets_IAT_max(packets)
            flows_dict[cnt]['Flow packet IAT min'] = flow_packets_IAT_min(packets)
            flows_dict[cnt]['Flow backward packet IAT sum'] = flow_packets_IAT_sum(packets)
            flows_dict[cnt]['Flow forward packet IAT mean'] = flow_fwdpackets_IAT_mean(flow)
            flows_dict[cnt]['Flow forward packet IAT std'] = flow_fwdpackets_IAT_std(flow)
            flows_dict[cnt]['Flow forward packet IAT max'] = flow_fwdpackets_IAT_max(flow)
            flows_dict[cnt]['Flow forward packet IAT min'] = flow_fwdpackets_IAT_min(flow)
            flows_dict[cnt]['Flow forward packet IAT sum'] = flow_fwdpackets_IAT_sum(flow)
            flows_dict[cnt]['Flow backward packet IAT mean'] = flow_bwdpackets_IAT_mean(flow)
            flows_dict[cnt]['Flow backward packet IAT std'] = flow_bwdpackets_IAT_std(flow)
            flows_dict[cnt]['Flow backward packet IAT max'] = flow_bwdpackets_IAT_max(flow)
            flows_dict[cnt]['Flow backward packet IAT min'] = flow_bwdpackets_IAT_min(flow)
            flows_dict[cnt]['Flow backward packet IAT sum'] = flow_bwdpackets_IAT_sum(flow)


            #packet length ##bflow
            flows_dict[cnt]['Bflow Packet Lenght Max'] = flow_packets_length_max(bpackets)
            flows_dict[cnt]['Bflow Packet Lenght Min'] = flow_packets_length_min(bpackets)
            flows_dict[cnt]['Bflow Packet Lenght Mean'] = flow_packets_length_mean(bpackets)
            flows_dict[cnt]['Bflow Packet Length Sum'] = flow_packets_length_sum(bpackets)
            flows_dict[cnt]['Bflow Packet Length Std'] = flow_packets_length_std(bpackets)



            #packet length ##fflow
            flows_dict[cnt]['Fflow Packet Lenght Max'] = flow_packets_length_max(fpackets)
            flows_dict[cnt]['Fflow Packet Lenght Min'] = flow_packets_length_min(fpackets)
            flows_dict[cnt]['Fflow Packet Lenght Mean'] = flow_packets_length_mean(fpackets)
            flows_dict[cnt]['Fflow Packet Lenght Sum'] = flow_packets_length_sum(fpackets)
            flows_dict[cnt]['Fflow Packet Lenght Std'] = flow_packets_length_std(fpackets)
            
            
            
            
            #flows_dict[cnt][''] = 
            #flows_dict[cnt][''] = 
            #flows_dict[cnt][''] = 
        
            
            
            

            
            
            
            
            
            #goes to the next flow
            cnt+=1
            
        df = pd.DataFrame.from_dict(flows_dict, orient='index')
        df.to_csv('TrafficFlow.csv')
        print('File has been created')
        


# In[149]:


#writing the csv
csvw = csv_writer()
csvw. create_csv(flows)

