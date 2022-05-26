from scapy.utils import rdpcap


class flow_capturer:

    def __init__(self):
        self.finished_flows = []
        self.current_flows = []
        self.all_flows = []

    def capture(self, pcap_file):
        packets = rdpcap(pcap_file)
        for pkt in packets:  ## Do we check other protocols?
            if TCP in pkt:
                packet = Packet(src_ip=pkt[IP].src, src_port=pkt[TCP].sport, dst_ip=pkt[IP].dst,
                                dst_port=pkt[TCP].dport, protocol=pkt[IP].proto,
                                flags=str(pkt[TCP].flags), timestamp=pkt.time, length=len(pkt))

                self.__add_packet_to_flow(packet)
        self.all_flows = self.finished_flows + self.current_flows
        return self.all_flows

    def __add_packet_to_flow(self, packet):
        flow = self.__search_for_flow(packet)
        if flow == None:
            self.__create_new_flow(packet)
        else:
            flow.add_packet(packet)
            if packet.has_flagFIN() == True:  ##add the other constraints
                self.finished_flows.append(flow)
                self.current_flows.remove(flow)

    def __search_for_flow(self, packet) -> object:
        for flow in self.current_flows:
            if (flow.get_src_ip() == packet.get_src_ip() or flow.get_src_ip() == packet.get_dst_ip()) and (
                    flow.get_dst_ip() == packet.get_src_ip() or flow.get_dst_ip() == packet.get_dst_ip()) and (
                    flow.get_src_port() == packet.get_src_port() or flow.get_src_port() == packet.get_dst_port()) and (
                    flow.get_dst_port() == packet.get_src_port() or flow.get_dst_port() == packet.get_dst_port()):

                if flow.get_src_ip() == packet.get_dst_ip():
                    packet.forward = False

                return flow

        return None

    def __create_new_flow(self, packet) -> None:
        new_flow = Flow(packet)
        new_flow.add_packet(packet)
        self.current_flows.append(new_flow)

