#!/usr/bin/env python3

import datetime
from datetime import datetime
import dpkt
import socket
from .packet import Packet
from .flow import Flow


class NetLayerFlowCapturer:
    def __init__(self, max_flow_duration: int, activity_timeout: int,
                check_flows_ending_min_flows: int, capturer_updating_flows_min_value: int,
                read_packets_count_value_log_info: int):
        self.__finished_flows = []
        self.__ongoing_flows = {}
        self.__max_flow_duration = max_flow_duration
        self.__activity_timeout = activity_timeout
        self.__check_flows_ending_min_flows = check_flows_ending_min_flows
        self.__capturer_updating_flows_min_value = capturer_updating_flows_min_value
        self.__read_packets_count_value_log_info = read_packets_count_value_log_info
        self.flows_counter = 0


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
                # if not isinstance(ip.data, dpkt.tcp.TCP) and \
                #     not isinstance(ip.data, dpkt.tcp.UDP):
                if not isinstance(ip.data, dpkt.tcp.TCP):
                    continue

                net_layer = ip.data
                network_protocol = None
                window_size = None
                tcp_flags = 0


                if isinstance(ip.data, dpkt.tcp.TCP):
                    network_protocol = 'TCP'
                    window_size = net_layer.win
                    tcp_flags = net_layer.flags
                    seq_number = net_layer.seq
                    ack_number = net_layer.ack
                else:
                    network_protocol = 'UDP'
                    window_size = 0
                    tcp_flags = 0
                    seq_number = 0
                    ack_number = 0

                nlflyzer_packet = Packet(
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
                    window_size=window_size,
                    seq_number=seq_number,
                    ack_number=ack_number)

                self.__add_packet_to_flow(nlflyzer_packet, flows, flows_lock)

                if i % self.__read_packets_count_value_log_info == 0:
                    print(">>", i, "number of packets has been processed...")

            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, Exception) as e:
                continue

        print(f">> End of reading from {pcap_file}")
        print(f">> {self.flows_counter} flows created in total.")
        print(">> Preparing the output file...")

        with flows_lock:
            flows.extend(self.__finished_flows)
            list_of_values = [self.__ongoing_flows[key] for key in self.__ongoing_flows]
            flows.extend(list_of_values)

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
                for oflow_id in self.__ongoing_flows:
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
