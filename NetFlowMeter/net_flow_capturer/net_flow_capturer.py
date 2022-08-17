#!/usr/bin/env python3

from multipledispatch import dispatch
from scapy.all import *
from .packet import Packet
from .flow import Flow


class NetFlowCapturer:
    def __init__(self,max_flow_duration,activity_timeout):
        self.finished_flows = []
        self.current_flows = []
        self.all_flows = []
        self.max_flow_duration = max_flow_duration
        self.activity_timeout = activity_timeout
 
    def capture(self, pcap_file):
        sniff(offline=pcap_file, prn=self.packet_processing, store=0)
        self.all_flows = self.finished_flows + self.current_flows
        return self.all_flows

    def packet_processing(self, scapy_packet):
        if IP not in scapy_packet:
            return
        if TCP in scapy_packet:
            packet = Packet(src_ip=scapy_packet[IP].src, src_port=scapy_packet[TCP].sport, dst_ip=scapy_packet[IP].dst,
                            dst_port=scapy_packet[TCP].dport, protocol=scapy_packet[IP].proto,
                            flags=str(scapy_packet[TCP].flags), timestamp=scapy_packet.time, length= len(scapy_packet),
                            payloadbytes=len(scapy_packet[TCP].payload))
            self.__add_packet_to_flow(packet)
        if UDP in scapy_packet:
            packet = Packet(src_ip=scapy_packet[IP].src, src_port=scapy_packet[UDP].sport, dst_ip=scapy_packet[IP].dst,
                            dst_port=scapy_packet[UDP].dport, protocol=scapy_packet[IP].proto,
                            timestamp=scapy_packet.time, length= len(scapy_packet),payloadbytes=len(scapy_packet[UDP].payload))

            self.__add_packet_to_flow(packet)
    
    def __add_packet_to_flow(self, packet):
        flow = self.__search_for_flow(packet)
        if flow == None:
            self.__create_new_flow(packet)
        else:

            if self.flow_is_ended(flow, packet):
                self.finished_flows.append(flow)
                self.current_flows.remove(flow)
                self.__create_new_flow(packet)
            else:
                flow.add_packet(packet)

    def flow_is_ended(self,flow,packet):
        flow_duration =flow.get_flow_last_seen() - flow.get_flow_start_time()
        active_time = packet.get_timestamp() - flow.get_flow_last_seen()
        if flow_duration > self.max_flow_duration or active_time > self.activity_timeout \
                 or packet.has_flagFIN() == True or packet.has_flagRST()==True:
            return True
        return False

    def __search_for_flow(self, packet) -> object:
        for flow in self.current_flows:
            if (flow.get_src_ip() == packet.get_src_ip() or flow.get_src_ip() == packet.get_dst_ip()) \
                    and (flow.get_dst_ip() == packet.get_src_ip() or flow.get_dst_ip() == packet.get_dst_ip()) \
                    and (flow.get_src_port() == packet.get_src_port() or flow.get_src_port() == packet.get_dst_port()) \
                    and (flow.get_dst_port() == packet.get_src_port() or flow.get_dst_port() == packet.get_dst_port()):
                
                if flow.get_src_ip() == packet.get_dst_ip():
                    packet.forward=False
                return flow
        return None

    def __create_new_flow(self, packet) -> None:
        new_flow = Flow(packet)
        new_flow.add_packet(packet)
        self.current_flows.append(new_flow)
