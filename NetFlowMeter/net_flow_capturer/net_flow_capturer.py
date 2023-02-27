#!/usr/bin/env python3

import datetime
from datetime import datetime
import dpkt
import socket
from .packet import Packet
from .flow import Flow


class NetFlowCapturer:
    def __init__(self, max_flow_duration: int, activity_timeout: int,
                check_flows_ending_min_flows: int, capturer_updating_flows_min_value: int,
                read_packets_count_value_log_info: int):
        self.__finished_flows = []
        self.__ongoing_flows = []
        self.__max_flow_duration = max_flow_duration
        self.__activity_timeout = activity_timeout
        self.__check_flows_ending_min_flows = check_flows_ending_min_flows
        self.__capturer_updating_flows_min_value = capturer_updating_flows_min_value
        self.__read_packets_count_value_log_info = read_packets_count_value_log_info


    def capture(self, pcap_file: str, flows: list, flows_lock, thread_finished) -> list:
        f = open(pcap_file, 'rb')
        pcap = dpkt.pcap.Reader(f)
        i = 0
        for ts, buf in pcap:
            i +=1
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                if not isinstance(ip.data, dpkt.udp.UDP) and \
                    not isinstance(ip.data, dpkt.tcp.TCP):
                    continue

            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, Exception) as e:
                continue
            
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

            net_layer = ip.data
            network_protocol = None
            window_size = None
            tcp_flags = None


            if isinstance(ip.data, dpkt.tcp.TCP):
                network_protocol = 'TCP'
                window_size = net_layer.win
                tcp_flags = net_layer.flags
            else:
                network_protocol = 'UDP'
                window_size = 0
                tcp_flags = 0

            net_flow_packet = Packet(
                src_ip=socket.inet_ntoa(ip.src), 
                src_port=net_layer.sport,
                dst_ip=socket.inet_ntoa(ip.dst), 
                dst_port=net_layer.dport,
                protocol=network_protocol, 
                flags=tcp_flags,
                timestamp=ts, 
                length=len(buf),
                payloadbytes=len(net_layer.data), 
                header_size=len(ip.data) - len(net_layer.data),
                window_size=window_size)

            self.__add_packet_to_flow(net_flow_packet, flows, flows_lock)

            if i % self.__read_packets_count_value_log_info == 0:
                print(">>", i, "number of packets has been processed...")

        with flows_lock:
            flows.extend(self.__finished_flows)
            flows.extend(self.__ongoing_flows)
        print(">> End of reading from", pcap_file)
        thread_finished.set(True)
        return flows
    

    def __add_packet_to_flow(self, packet: Packet, flows: list, flows_lock) -> None:
        flow = self.__search_for_flow(packet)
        if flow == None:
            self.__create_new_flow(packet)
            return

        if self.flow_is_ended(flow, packet):
            self.__finished_flows.append(flow)
            self.__ongoing_flows.remove(flow)
            self.__create_new_flow(packet)

            if len(self.__ongoing_flows) >= self.__check_flows_ending_min_flows:
                for oflow in self.__ongoing_flows:
                    if oflow.actvity_timeout(packet):
                        self.__ongoing_flows.remove(oflow)
                        self.__finished_flows.append(oflow)
            if len(self.__finished_flows) >= self.__capturer_updating_flows_min_value:
                with flows_lock:
                    flows.extend(self.__finished_flows)
                    self.__finished_flows.clear()
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
        for flow in self.__ongoing_flows:
            if (flow.get_src_ip() == packet.get_src_ip() or flow.get_src_ip() == packet.get_dst_ip()) \
                    and (flow.get_dst_ip() == packet.get_src_ip() or flow.get_dst_ip() == packet.get_dst_ip()) \
                    and (flow.get_src_port() == packet.get_src_port() or flow.get_src_port() == packet.get_dst_port()) \
                    and (flow.get_dst_port() == packet.get_src_port() or flow.get_dst_port() == packet.get_dst_port()) \
                    and (flow.get_protocol() == packet.get_protocol()) \
                    and (datetime.fromtimestamp(float(flow.get_timestamp())) <= datetime.fromtimestamp(float(packet.get_timestamp()))):
                
                if flow.get_src_ip() == packet.get_dst_ip():
                    packet.forward=False
                return flow
        return None

    def __create_new_flow(self, packet) -> None:
        new_flow = Flow(packet, self.__activity_timeout)
        new_flow.add_packet(packet)
        self.__ongoing_flows.append(new_flow)
