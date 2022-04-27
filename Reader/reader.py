import scapy
from scapy.all import *

class flow_capturer:
    
    def __init__(self):
        self.finished_flows = []
        self.current_flows = []
        
    def capture(self, pcap_file):
        packets = rdpcap(pcap_file)
        for pkt in packets: ## Do we check other protocols?
            if TCP in pkt:
                packet = Packet(pkt[IP].src, pkt[TCP].sport, pkt[IP].dst ,pkt[TCP].dport, pkt[IP].proto, str(pkt[TCP].flags), pkt.time)
            
                self.__add_packet_to_flow(packet)
        return self.finished_flows.extend(current_flows)
    
     def __add_packet_to_flow(self, packet):
        flow = self.__search_for_flow(packet)
        if flow == None:
            self.__create_new_flow(packet)
        else:
            flow.add_packet(packet)
            if packet.has_flagFIN() == True: ##add the other constraints
                finished_flows.append(flow)
                current_flows.remove(flow)


    def __search_for_flow(self, packet) -> object:
        for flow in self.current_flows:
            if (flow.get_src_ip() == packet.get_src_ip() or flow.get_src_ip() == packet.get_dst_ip()) and \
               (flow.get_dst_ip() == packet.get_src_ip() or flow.get_dst_ip() == packet.get_dst_ip()) and \
               (flow.get_src_port() == packet.get_src_port() or flow.get_src_port() == packet.get_dst_port()) and \
               (flow.get_dst_port() == packet.get_src_port() or flow.get_dst_port() == packet.get_dst_port()):
                
                if flow.get_src_ip() == packet.get_dst_ip():
                    packet.forward=False
                    
                   return flow

        return None

    def __create_new_flow(self, packet) -> None:
        new_flow = Flow(packet)
        new_flow.add_packet(packet)
        self.current_flows.append(new_flow)

    
