#!/usr/bin/env python3

import datetime
from datetime import datetime
import dpkt
from dpkt import ethernet
import socket
import os
import time
from collections import defaultdict, Counter
from .packet import Packet
from .flow import Flow


class NetworkFlowCapturer:
    def __init__(self, max_flow_duration: int, activity_timeout: int,
                check_flows_ending_min_flows: int, capturer_updating_flows_min_value: int,
                read_packets_count_value_log_info: int, vxlan_ip: str,
                continues_batch_address: str, continues_pcap_prefix: str,
                number_of_continues_files: int, continues_batch_mode: bool):
        self.__finished_flows = []
        self.__ongoing_flows = {}
        self.__max_flow_duration = max_flow_duration
        self.__activity_timeout = activity_timeout
        self.__check_flows_ending_min_flows = check_flows_ending_min_flows
        self.__capturer_updating_flows_min_value = capturer_updating_flows_min_value
        self.__read_packets_count_value_log_info = read_packets_count_value_log_info
        self.__vxlan_ip = vxlan_ip
        self.__continues_batch_address = continues_batch_address
        self.__continues_pcap_prefix = continues_pcap_prefix
        self.__number_of_continues_files = number_of_continues_files
        self.__continues_batch_mode = continues_batch_mode
        self.flows_counter = 0
        self.tcp_packets = 0
        self.udp_packets = 0
        self.ip_packets = 0
        self.all_packets = 0


    def pcap_summary(self, address):
        ip_count, tcp_count, udp_count = 0, 0, 0
        app_protocol_count = defaultdict(int)
        f = open(address, 'rb')

        pcap = dpkt.pcap.Reader(f)
        total_packets = 0

        for ts, buf in pcap:
            total_packets += 1
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                decapsulation = True
                while decapsulation:
                    if not isinstance(eth.data, dpkt.ip.IP):
                        decapsulation = False
                        break
                    ip = eth.data
                    if (socket.inet_ntoa(ip.src) == self.__vxlan_ip) or (socket.inet_ntoa(ip.dst) == self.__vxlan_ip):

                        if not ((socket.inet_ntoa(ip.src) == self.__vxlan_ip and socket.inet_ntoa(ip.dst)[0:5] == "10.0.") or \
                            (socket.inet_ntoa(ip.dst) == self.__vxlan_ip and socket.inet_ntoa(ip.src)[0:5] == "10.0.")):
                            decapsulation = False
                            break

                        if len(eth.data.data.data) == 0:
                            decapsulation = False
                            break

                        # To understand what is happening here, I recommend you to check the packets in wireshark
                        new_buf = eth.data.data.data
                        if isinstance(eth.data.data, dpkt.icmp.ICMP):
                            new_buf = eth.data.data.data.data.data.data
                        new_buf = new_buf[8:] # Passing the vxlan
                        eth = ethernet.Ethernet(new_buf)
                    else:
                        decapsulation = False
                        break

                if not isinstance(eth.data, dpkt.ip.IP):
                    continue

                if (socket.inet_ntoa(ip.src) == self.__vxlan_ip) or (socket.inet_ntoa(ip.dst) == self.__vxlan_ip):
                    if len(eth.data.data.data) == 0:
                        continue
                ip_count += 1

                if isinstance(ip.data, dpkt.udp.UDP):
                    udp_count += 1
                    app_protocol_count[eth.data.data.dport] += 1
                    continue

                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp_count += 1
                    app_protocol_count[eth.data.data.dport] += 1


            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, Exception) as e:
                print(f"ERROR in packet number {total_packets}")
                print(e)
                continue

        print(50 * "=")
        print("Number and percentage of IP packets:")
        print(f"  Total IP packets: {ip_count}")
        print(f"  Percentage of IP packets: {(ip_count / total_packets) * 100:.2f}%\n")

        print("Number and percentage of TCP packets:")
        print(f"  Total TCP packets: {tcp_count}")
        print(f"  Percentage of TCP packets: {(tcp_count / total_packets) * 100:.2f}%\n")

        print("Number and percentage of UDP packets:")
        print(f"  Total UDP packets: {udp_count}")
        print(f"  Percentage of UDP packets: {(udp_count / total_packets) * 100:.2f}%\n")

        top_protocols = Counter(app_protocol_count).most_common(10)
        print("Top 10 Application Layer Protocols:")
        for port, count in top_protocols:
            protocol_name = self.get_protocol_name(port)
            print(f"  Port {port} ({protocol_name}): {count} packets, {(count / total_packets) * 100:.2f}%")

        print(50 * "=")
        self.ip_packets += ip_count
        self.tcp_packets += tcp_count
        self.udp_packets += udp_count
        self.all_packets += total_packets
        f.close()

    def get_protocol_name(self, port):
        protocol_names = {
            80: "HTTP",
            443: "HTTPS",
            21: "FTP",
            22: "SSH",
            25: "SMTP",
            110: "POP3",
            143: "IMAP",
            53: "DNS",
            137: "NetBIOS-NS",
            3389: "RDP",
        }
        return protocol_names.get(port, "Unknown")


    def pcap_parser(self, pcap_file: str, flows: list, flows_lock):
        print(f">> Analyzing {pcap_file}")
        self.packet_counter = 0
        self.pcap_summary(pcap_file)
        f = open(pcap_file, 'rb')
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            self.packet_counter +=1
            try:
                new_buf = buf
                eth = dpkt.ethernet.Ethernet(buf)

                decapsulation = True
                while decapsulation:
                    if not isinstance(eth.data, dpkt.ip.IP):
                        decapsulation = False
                        break
                    ip = eth.data
                    if (socket.inet_ntoa(ip.src) == self.__vxlan_ip) or (socket.inet_ntoa(ip.dst) == self.__vxlan_ip):
                        if not ((socket.inet_ntoa(ip.src) == self.__vxlan_ip and socket.inet_ntoa(ip.dst)[0:5] == "10.0.") or \
                            (socket.inet_ntoa(ip.dst) == self.__vxlan_ip and socket.inet_ntoa(ip.src)[0:5] == "10.0.")):
                            decapsulation = False
                            break

                        # To understand what is happening here, I recommend you to check the packets in wireshark
                        new_buf = eth.data.data.data
                        if isinstance(eth.data.data, dpkt.icmp.ICMP):
                            new_buf = eth.data.data.data.data.data.data

                        new_buf = new_buf[8:] # Passing the vxlan
                        eth = dpkt.ethernet.Ethernet(new_buf)
                    else:
                        decapsulation = False
                        break
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data

                if not isinstance(ip.data, dpkt.tcp.TCP):
                    continue

                if (socket.inet_ntoa(ip.src) == self.__vxlan_ip) or (socket.inet_ntoa(ip.dst) == self.__vxlan_ip):

                    if not ((socket.inet_ntoa(ip.src) == self.__vxlan_ip and socket.inet_ntoa(ip.dst)[0:5] == "10.0.") or \
                        (socket.inet_ntoa(ip.dst) == self.__vxlan_ip and socket.inet_ntoa(ip.src)[0:5] == "10.0.")):
                        continue

                if not isinstance(ip.data, dpkt.tcp.TCP):
                    continue

                tcp_layer = ip.data
                network_protocol = 'TCP'
                window_size = tcp_layer.win
                tcp_flags = tcp_layer.flags
                seq_number = tcp_layer.seq
                ack_number = tcp_layer.ack

                nlflyzer_packet = Packet(
                    src_ip=socket.inet_ntoa(ip.src), 
                    src_port=tcp_layer.sport,
                    dst_ip=socket.inet_ntoa(ip.dst), 
                    dst_port=tcp_layer.dport,
                    protocol=network_protocol, 
                    flags=tcp_flags,
                    timestamp=ts, 
                    length=len(new_buf),
                    payloadbytes=len(tcp_layer.data), 
                    header_size=len(ip.data) - len(tcp_layer.data),
                    window_size=window_size,
                    seq_number=seq_number,
                    ack_number=ack_number)
                
                self.__add_packet_to_flow(nlflyzer_packet, flows, flows_lock)

                if self.packet_counter % self.__read_packets_count_value_log_info == 0:
                    print(f">> {self.packet_counter} number of packets has been processed...")

            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, Exception) as e:
                print(f"!! Exception happened!")
                print(f"packet number: {self.packet_counter}")
                print(e)
                print(30*"*")
                continue
        f.close()


    def capture(self, pcap_file: str, flows: list, flows_lock, thread_finished) -> list:
        print(">> Parser has started...")
        if self.__continues_batch_mode is True:
            print(">> Continues Batch mode is on!")
            for i in self.__number_of_continues_files:
                filename = self.__continues_pcap_prefix + str(i)
                continues_pcap_file = os.path.join(self.__continues_batch_address, filename)
                self.pcap_parser(pcap_file=continues_pcap_file, flows=flows, flows_lock=flows_lock)

        else:
            self.pcap_parser(pcap_file=pcap_file, flows=flows, flows_lock=flows_lock)

        print(f">> End of parsing pcap file(s).")
        print(f">>> {self.packet_counter} packets analyzed and {self.flows_counter} flows created in total.")

        with flows_lock:
            flows.extend(self.__finished_flows)
            list_of_values = [self.__ongoing_flows[key] for key in self.__ongoing_flows]
            flows.extend(list_of_values)

        print(50 * "#")
        print(">> Parser Report:")
        print(50 * "#")
        print(">>> Number and percentage of IP packets:")
        print(f"      Total IP packets: {self.ip_packets}")
        print(f"      Percentage of IP packets: {(self.ip_packets / self.all_packets) * 100:.2f}%\n")

        print(">>> Number and percentage of TCP packets:")
        print(f"      Total TCP packets: {self.tcp_packets}")
        print(f"      Percentage of TCP packets: {(self.tcp_packets / self.all_packets) * 100:.2f}%\n")

        print(">>> Number and percentage of UDP packets:")
        print(f"      Total UDP packets: {self.udp_packets}")
        print(f"      Percentage of UDP packets: {(self.udp_packets / self.all_packets) * 100:.2f}%\n")
        print(50 * "#")

        print(">> Preparing the output file...")

        thread_finished.set(True)

    def __add_packet_to_flow(self, packet: Packet, flows: list, flows_lock) -> None:
        flow_id_dict = self.__search_for_flow(packet)

        if flow_id_dict == None:
            self.__create_new_flow(packet)
            return
        flow = self.__ongoing_flows[flow_id_dict]
        if self.flow_is_ended(flow, packet):
            self.__finished_flows.append(flow)
            del self.__ongoing_flows[flow_id_dict]
            self.__create_new_flow(packet)

            if len(self.__finished_flows) >= self.__capturer_updating_flows_min_value:
                with flows_lock:
                    for ff in self.__finished_flows:
                        flows.append(ff)
                    self.__finished_flows.clear()

            if len(self.__ongoing_flows) >= self.__check_flows_ending_min_flows:
                for oflow_id in self.__ongoing_flows.copy():
                    oflow = self.__ongoing_flows[oflow_id]
                    if oflow.actvity_timeout(packet):
                        self.__finished_flows.append(oflow)
                        del self.__ongoing_flows[oflow_id]

            return

        flow.add_packet(packet)

    def flow_is_ended(self,flow,packet):
        flow_duration = datetime.fromtimestamp(float(packet.get_timestamp())) - datetime.fromtimestamp(float(flow.get_flow_start_time()))
        active_time = datetime.fromtimestamp(float(packet.get_timestamp())) - datetime.fromtimestamp(float(flow.get_flow_last_seen()))
        if flow_duration.total_seconds() > self.__max_flow_duration \
                or active_time.total_seconds() > self.__activity_timeout \
                or flow.has_two_FIN_flags() \
                or flow.has_flagRST():
            return True
        return False

    def __search_for_flow(self, packet) -> object:
        flow_id_dict = str(packet.get_src_ip()) + '_' + str(packet.get_src_port()) + \
                       '_' + str(packet.get_dst_ip()) + '_' + str(packet.get_dst_port()) + \
                       '_' + str(packet.get_protocol())

        alternative_flow_id_dict = str(packet.get_dst_ip()) + '_' + str(packet.get_dst_port()) + \
                                   '_' + str(packet.get_src_ip()) + '_' + str(packet.get_src_port()) + \
                                   '_' + str(packet.get_protocol())

        if alternative_flow_id_dict in self.__ongoing_flows:
            packet.forward = False
            return alternative_flow_id_dict

        if flow_id_dict in self.__ongoing_flows:
            return flow_id_dict
        return None

    def __create_new_flow(self, packet) -> None:
        self.flows_counter += 1
        new_flow = Flow(packet, self.__activity_timeout)
        new_flow.add_packet(packet)
        flow_id_dict = str(packet.get_src_ip()) + '_' + str(packet.get_src_port()) + \
                       '_' + str(packet.get_dst_ip()) + '_' + str(packet.get_dst_port()) + \
                       '_' + str(packet.get_protocol())
        self.__ongoing_flows[flow_id_dict] = new_flow
