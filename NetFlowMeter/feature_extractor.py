#!/usr/bin/env python3

from datetime import datetime
from .features import *


class FeatureExtractor(object):
    def __init__(self, flows: list, floating_point_unit: str):
        self.__flows = flows
        self.floating_point_unit = floating_point_unit
        self.__features = [
                Duration(),
                PacketsNumbers(),
                ReceivingPacketsNumbers(),
                SendingPacketsNumbers(),
            ]


    def execute(self, features_ignore_list: list = []) -> list:
        self.__extracted_data = []
        for flow in self.__flows:
            features_of_flow = {}
            features_of_flow["flow_id"] = str(flow)
            features_of_flow["timestamp"] = datetime.fromtimestamp(flow.get_timestamp())
            features_of_flow["src_ip"] = flow.get_src_ip()
            features_of_flow["src_port"] = flow.get_src_port()
            features_of_flow["dst_ip"] = flow.get_dst_ip()
            features_of_flow["dst_port"] = flow.get_dst_port()
            features_of_flow["protocol"] = flow.get_protocol()
            for feature in self.__features:
                if feature.name in features_ignore_list:
                    continue
                feature.set_floating_point_unit(self.floating_point_unit)
                features_of_flow[feature.name] = feature.extract(flow)
            self.__extracted_data.append(features_of_flow.copy())
        return self.__extracted_data.copy()




class Features:  #TODO: should create a Features class
    def all_features(self,pcap_file_name,flow_time_out, actively_time_out):
        capturer = flow_capturer(flow_time_out, actively_time_out)  #TODO: Can be managed by config file so there will not be any need for writing the numbers
        flows_list = capturer.capture(pcap_file_name)

#        flows_dict = {}
        flows_data_list = []
        # cnt = 0
        # each flow:

        for flow in flows_list:
            flow_data = {}
            packets = flow.get_packets()
            bpackets = flow.get_backwardpackets()
            fpackets = flow.get_forwardpackets()
            # flow identifications
            flow_data['Flow Id'] = flow.get_flow_id()
            # print(flow_data['Flow Id'])
            flow_data['Source IP'] = flow.get_src_ip()
            flow_data['Source Port'] = flow.get_src_port()
            flow_data['Destination IP'] = flow.get_dst_ip()
            flow_data['Destination Port'] = flow.get_dst_port()
            flow_data['Protocol'] = flow.get_protocol()
            flow_data['timestamp'] = flow.get_flow_start_time()

            #segment size
            flow_data['average_segment_size']=avg_segment_size(flow)
            flow_data['forward_average_segment_size'] = fwd_avg_segment_size(flow)
            flow_data['backward_average_segment_size'] = bwd_avg_segment_size(flow)
            #payload_bytes
            flow_data['total_pay_load']=flow.total_packets_payloadbytes()
            flow_data['pay_load'] = payload_bytes(flow)


            # flags ##flow
            flow_data['Flow # FIN'] = fin_flag_counts(packets)
            flow_data['Flow # PSH'] = psh_flag_counts(packets)
            flow_data['Flow # URG'] = urg_flag_counts(packets)
            flow_data['Flow # ECE'] = ece_flag_counts(packets)
            flow_data['Flow # SYN'] = syn_flag_counts(packets)
            flow_data['Flow # ACK'] = ack_flag_counts(packets)
            flow_data['Flow # CWR'] = cwr_flag_counts(packets)
            flow_data['Flow # RST'] = rst_flag_counts(packets)
            # flags ##backwrd
            flow_data['Bflow # FIN'] = fin_flag_counts(bpackets)
            flow_data['Bflow # PSH'] = psh_flag_counts(bpackets)
            flow_data['Bflow # URG'] = urg_flag_counts(bpackets)
            flow_data['Bflow # ECE'] = ece_flag_counts(bpackets)
            flow_data['Bflow # SYN'] = syn_flag_counts(bpackets)
            flow_data['Bflow # ACK'] = ack_flag_counts(bpackets)
            flow_data['Bflow # CWR'] = cwr_flag_counts(bpackets)
            flow_data['Bflow # RST'] = rst_flag_counts(bpackets)
            # flags ##forward
            flow_data['Fflow # FIN'] = fin_flag_counts(fpackets)
            flow_data['Fflow # PSH'] = psh_flag_counts(fpackets)
            flow_data['Fflow # URG'] = urg_flag_counts(fpackets)
            flow_data['Fflow # ECE'] = ece_flag_counts(fpackets)
            flow_data['Fflow # SYN'] = syn_flag_counts(fpackets)
            flow_data['Fflow # ACK'] = ack_flag_counts(fpackets)
            flow_data['Fflow # CWR'] = cwr_flag_counts(fpackets)
            flow_data['Fflow # RST'] = rst_flag_counts(fpackets)
            # time
            flow_data['Flow Duration'] = flow_duration(flow)
            # packet counts ##flow
            flow_data['Flow # Packets'] = packet_count(packets)
            flow_data['Flow # Packets Per Second'] = flow_packets_per_second(flow)
            # packet counts ##backward
            flow_data['BFlow # Packets'] = packet_count(bpackets)
            flow_data['Bflow # Packets Per Second'] = bflow_packets_per_second(flow)
            # packet counts ##forward
            flow_data['Fflow # packets'] = packet_count(fpackets)
            flow_data['Fflow # Packets Per Second'] = fflow_packets_per_second(flow)
            # packet length ##flow
            flow_data['Flow Packet Length Max'] = flow_packets_length_max(packets)
            flow_data['Flow Packet Length Min'] = flow_packets_length_min(packets)
            flow_data['Flow Packet Length Mean'] = flow_packets_length_mean(packets)
            flow_data['Flow Packet Length Sum'] = flow_packets_length_sum(packets)
            flow_data['Flow Packet Length Std'] = flow_packets_length_std(packets)
            # packet length ##backward
            flow_data['Bflow Packet Length Max'] = flow_packets_length_max(bpackets)
            flow_data['Bflow Packet Length Min'] = flow_packets_length_min(bpackets)
            flow_data['Bflow Packet Length Mean'] = flow_packets_length_mean(bpackets)
            flow_data['Bflow Packet Length Sum'] = flow_packets_length_sum(bpackets)
            flow_data['Bflow Packet Length Std'] = flow_packets_length_std(bpackets)
            # packet length ##forward
            flow_data['Fflow Packet Length Max'] = flow_packets_length_max(fpackets)
            flow_data['Fflow Packet Length Min'] = flow_packets_length_min(fpackets)
            flow_data['Fflow Packet Length Mean'] = flow_packets_length_mean(fpackets)
            flow_data['Fflow Packet Length Sum'] = flow_packets_length_sum(fpackets)
            flow_data['Fflow Packet Length Std'] = flow_packets_length_std(fpackets)
            # iat ##flow
            flow_data['Flow Packet IAT Mean'] = flow_packets_IAT_mean(packets)
            flow_data['Flow packet IAT Std'] = flow_packets_IAT_std(packets)
            flow_data['Flow packet IAT max'] = flow_packets_IAT_max(packets)
            flow_data['Flow packet IAT min'] = flow_packets_IAT_min(packets)
            flow_data['Flow Packet IAT Sum'] = flow_packets_IAT_sum(packets)
            # iat ##forward
            flow_data['Flow forward packet IAT mean'] = flow_packets_IAT_mean(fpackets)
            flow_data['Flow forward packet IAT std'] = flow_packets_IAT_std(fpackets)
            flow_data['Flow forward packet IAT max'] = flow_packets_IAT_max(fpackets)
            flow_data['Flow forward packet IAT min'] = flow_packets_IAT_min(fpackets)
            flow_data['Flow forward packet IAT sum'] = flow_packets_IAT_sum(fpackets)
            # iat ##backward
            flow_data['Flow backward packet IAT mean'] = flow_packets_IAT_mean(bpackets)
            flow_data['Flow backward packet IAT std'] = flow_packets_IAT_std(bpackets)
            flow_data['Flow backward packet IAT max'] = flow_packets_IAT_max(bpackets)
            flow_data['Flow backward packet IAT min'] = flow_packets_IAT_min(bpackets)
            flow_data['Flow backward packet IAT sum'] = flow_packets_IAT_sum(bpackets)

            # idle,active
            flow_data['Active Min'] = active_min(flow)
            flow_data['Active Min'] = active_max(flow)
            flow_data['Active Min'] = active_mean(flow)
            flow_data['Active Min'] = active_std(flow)
            flow_data['Idle Min'] = idle_min(flow)
            flow_data['Idle Max'] = idle_max(flow)
            flow_data['Idle Mean'] = idle_mean(flow)
            flow_data['Idle std'] = idle_std(flow)

            # payload
            flow_data['Flow Bytes'] = flow_bytes(flow)
            flow_data['Flow Bytes per Second'] = flow_bytes_per_second(flow)
            flow_data['Fwd Flow Bytes'] = fwd_flow_bytes(flow)
            flow_data['Fwd Flow Bytes per Second'] = fwd_flow_bytes_per_second(flow)
            flow_data['Bwd Flow Bytes'] = bwd_flow_bytes(flow)
            flow_data['Bwd Flow Bytes per Second'] = bwd_flow_bytes_per_second(flow)


            #Bulk
            flow_data['Forward bulk state count']=flow.fBulkStateCount()
            flow_data['forward bulk total size']=flow.fBulkSizeTotal()
            flow_data['forward bulk per packet'] = flow.fBulkPacketCount()
            flow_data['forward bulk Duration'] = flow.fBulkDuration()
            flow_data['forward average bytes per bulk']=fAvgBytesPerBulk(flow)
            flow_data['forward average packet per bulk rate']=fAvgPacketsPerBulk(flow)
            flow_data['forward average bulks rate']=fAvgBulkRate(flow)

            flow_data['Backward bulk state count'] = flow.bBulkStateCount()
            flow_data['Backward bulk total size'] = flow.bBulkSizeTotal()
            flow_data['Backward bulk per packet'] = flow.bBulkPacketCount()
            flow_data['Backward bulk Duration'] = flow.bBulkDuration()
            flow_data['Backward average bytes per bulk'] = bAvgBytesPerBulk(flow)
            flow_data['Backward average packet per bulk rate'] = bAvgPacketsBulkRate(flow)
            flow_data['Backward average bulks rate'] =bAvgBulkRate(flow)
            # goes to the next flow
            flows_data_list.append(flow_data.copy())
        return flows_data_list



all_features=Features()
flows_dict=all_features.all_features('test.pcap',120000,5000)

csvw.write("NetFlowMeter.csv",flows_dict)


