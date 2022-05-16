#!/usr/bin/env python
# coding: utf-8

# In[1]:

import scapy
from scapy.all import *


# In[2]:


import pandas as pd


# In[22]:


import statistics
from statistics import *


# In[3]:


class Packet():
    
    def __init__(self, src_ip=" ", src_port=0, dst_ip=" ", dst_port=0, protocol=0, flags="", timestamp=0, forward=True):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.flags = flags
        self.timestamp = timestamp
        self.forward = forward
        
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


# In[4]:


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
        


# In[5]:


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
                                flags=str(pkt[TCP].flags), timestamp=pkt.time)
            
                self.__add_packet_to_flow(packet)
        self.all_flows = self.finished_flows + self.current_flows
        return self.all_flows
    
    def __add_packet_to_flow(self, packet):
        flow = self.__search_for_flow(packet)
        if flow == None:
            self.__create_new_flow(packet)
        else:
            flow.add_packet(packet)  ###????? does not work
            if packet.has_flagFIN() == True: ##add the other constraints
                self.finished_flows.append(flow)
                self.current_flows.remove(flow)


    def __search_for_flow(self, packet) -> object:
        for flow in self.current_flows:
            if (flow.get_src_ip() == packet.get_src_ip() or flow.get_src_ip() == packet.get_dst_ip()) and                (flow.get_dst_ip() == packet.get_src_ip() or flow.get_dst_ip() == packet.get_dst_ip()) and                (flow.get_src_port() == packet.get_src_port() or flow.get_src_port() == packet.get_dst_port()) and                (flow.get_dst_port() == packet.get_src_port() or flow.get_dst_port() == packet.get_dst_port()):
                
                if flow.get_src_ip() == packet.get_dst_ip():
                    packet.forward=False
                    
                return flow

        return None

    def __create_new_flow(self, packet) -> None:
        new_flow = Flow(packet)
        new_flow.add_packet(packet)
        self.current_flows.append(new_flow)


# In[ ]:


#capturing flows

capturer = flow_capturer()
flows = capturer.capture("data.pcap")


# In[67]:


#write the feature functions here

def fin_flag_counts(packets): #changed
    counts = 0
    for packet in flow.get_packets():
        if packet.has_flagFIN:
            counts+=1

def flow_duration(flow):
    return flow.get_flow_last_seen() - flow.get_flow_start_time()

def packet_count(packets):
    return len(packets)


# In[68]:


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
            flows_dict[cnt]['Flow Id'] = flow.get_flow_id()
            flows_dict[cnt]['Source IP'] = flow.get_src_ip()
            flows_dict[cnt]['Source Port'] = flow.get_src_port()
            flows_dict[cnt]['Destination IP'] = flow.get_dst_ip()
            flows_dict[cnt]['Destination Port'] = flow.get_dst_port()
            flows_dict[cnt]['Protocol'] = flow.get_protocol()
            flows_dict[cnt]['Flow # FIN'] = fin_flag_counts(packets)
            flows_dict[cnt]['Flow Duration'] = flow_duration(flow)
            flows_dict[cnt]['flow # packets'] = packet_count(packets)
            #add other features
            
            
            

            
            
            
            
            
            #goes to the next flow
            cnt+=1
            
        df = pd.DataFrame.from_dict(flows_dict, orient='index')
        df.to_csv('TrafficFlow.csv')
        #print('File has been created')
        


# In[69]:


#writing the csv
csvw = csv_writer()
csvw. create_csv(flows)

