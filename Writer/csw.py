import pandas as pd

from Features.features import fin_flag_counts, psh_flag_counts, urg_flag_counts, ece_flag_counts, syn_flag_counts, \
    ack_flag_counts, cwr_flag_counts, rst_flag_counts, flow_duration, packet_count, flow_packets_per_second, \
    bflow_packets_per_second, fflow_packets_per_second, flow_packets_length_max, flow_packets_length_min, \
    flow_packets_length_mean, flow_packets_length_sum, flow_packets_length_std, flow_packets_IAT_mean, \
    flow_packets_IAT_std, flow_packets_IAT_max, flow_packets_IAT_min, flow_packets_IAT_sum, flow_fwdpackets_IAT_mean, \
    flow_fwdpackets_IAT_std, flow_fwdpackets_IAT_max, flow_fwdpackets_IAT_min, flow_fwdpackets_IAT_sum, \
    flow_bwdpackets_IAT_mean, flow_bwdpackets_IAT_std, flow_bwdpackets_IAT_max, flow_bwdpackets_IAT_min, \
    flow_bwdpackets_IAT_sum, Get_down_up_ratio, Get_idle_min, Get_idle_max, Get_idle_std, get_idle_mean



class csv_writer:

    def create_csv(self, flows_list):
        flows_dict = {}
        cnt = 0
        # each flow:
        for flow in flows_list:
            packets = flow.get_packets()
            bpackets = flow.get_backwardpackets()
            fpackets = flow.get_forwardpackets()

            flows_dict[cnt] = {}
            # flow identifications
            flows_dict[cnt]['Flow Id'] = flow.get_flow_id()
            flows_dict[cnt]['Source IP'] = flow.get_src_ip()
            flows_dict[cnt]['Source Port'] = flow.get_src_port()
            flows_dict[cnt]['Destination IP'] = flow.get_dst_ip()
            flows_dict[cnt]['Destination Port'] = flow.get_dst_port()
            flows_dict[cnt]['Protocol'] = flow.get_protocol()
            # flags ##flow
            flows_dict[cnt]['Flow # FIN'] = fin_flag_counts(packets)
            flows_dict[cnt]['Flow # PSH'] = psh_flag_counts(packets)
            flows_dict[cnt]['Flow # URG'] = urg_flag_counts(packets)
            flows_dict[cnt]['Flow # ECE'] = ece_flag_counts(packets)
            flows_dict[cnt]['Flow # SYN'] = syn_flag_counts(packets)
            flows_dict[cnt]['Flow # ACK'] = ack_flag_counts(packets)
            flows_dict[cnt]['Flow # CWR'] = cwr_flag_counts(packets)
            flows_dict[cnt]['Flow # RST'] = rst_flag_counts(packets)
            # flags ##bflow
            flows_dict[cnt]['Bflow # FIN'] = fin_flag_counts(bpackets)
            flows_dict[cnt]['Bflow # PSH'] = psh_flag_counts(bpackets)
            flows_dict[cnt]['Bflow # URG'] = urg_flag_counts(bpackets)
            flows_dict[cnt]['Bflow # ECE'] = ece_flag_counts(bpackets)
            flows_dict[cnt]['Bflow # SYN'] = syn_flag_counts(bpackets)
            flows_dict[cnt]['Bflow # ACK'] = ack_flag_counts(bpackets)
            flows_dict[cnt]['Bflow # CWR'] = cwr_flag_counts(bpackets)
            flows_dict[cnt]['Bflow # RST'] = rst_flag_counts(bpackets)
            # flags ##fflow
            flows_dict[cnt]['Fflow # FIN'] = fin_flag_counts(fpackets)
            flows_dict[cnt]['Fflow # PSH'] = psh_flag_counts(fpackets)
            flows_dict[cnt]['Fflow # URG'] = urg_flag_counts(fpackets)
            flows_dict[cnt]['Fflow # ECE'] = ece_flag_counts(fpackets)
            flows_dict[cnt]['Fflow # SYN'] = syn_flag_counts(fpackets)
            flows_dict[cnt]['Fflow # ACK'] = ack_flag_counts(fpackets)
            flows_dict[cnt]['Fflow # CWR'] = cwr_flag_counts(fpackets)
            flows_dict[cnt]['Fflow # RST'] = rst_flag_counts(fpackets)
            # time
            flows_dict[cnt]['Flow Duration'] = flow_duration(flow)
            # packet counts ##flow
            flows_dict[cnt]['Flow # Packets'] = packet_count(packets)
            flows_dict[cnt]['Flow # Packets Per Second'] = flow_packets_per_second(flow)
            # packet counts ##bflow
            flows_dict[cnt]['BFlow # Packets'] = packet_count(bpackets)
            flows_dict[cnt]['Bflow # Packets Per Second'] = bflow_packets_per_second(flow)
            # packet counts ##fflow
            flows_dict[cnt]['Fflow # packets'] = packet_count(fpackets)
            flows_dict[cnt]['Fflow # Packets Per Second'] = fflow_packets_per_second(flow)
            # packet length ##flow
            flows_dict[cnt]['Flow Packet Lenght Max'] = flow_packets_length_max(packets)
            flows_dict[cnt]['Flow Packet Lenght Min'] = flow_packets_length_min(packets)
            flows_dict[cnt]['Flow Packet Lenght Mean'] = flow_packets_length_mean(packets)
            flows_dict[cnt]['Flow Packet Lenght Sum'] = flow_packets_length_sum(packets)
            flows_dict[cnt]['Flow Packet Lenght Std'] = flow_packets_length_std(packets)

            # IAT features## packets#
            flows_dict[cnt]['Flow packet IAT mean'] = flow_packets_IAT_mean(packets)  # should be improved
            flows_dict[cnt]['Flow packet IAT std'] = flow_packets_IAT_std(packets)  # should be improved
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

            # packet length ##bflow
            flows_dict[cnt]['Bflow Packet Lenght Max'] = flow_packets_length_max(bpackets)
            flows_dict[cnt]['Bflow Packet Lenght Min'] = flow_packets_length_min(bpackets)
            flows_dict[cnt]['Bflow Packet Lenght Mean'] = flow_packets_length_mean(bpackets)
            flows_dict[cnt]['Bflow Packet Length Sum'] = flow_packets_length_sum(bpackets)
            flows_dict[cnt]['Bflow Packet Length Std'] = flow_packets_length_std(bpackets)

            # packet length ##fflow
            flows_dict[cnt]['Fflow Packet Lenght Max'] = flow_packets_length_max(fpackets)
            flows_dict[cnt]['Fflow Packet Lenght Min'] = flow_packets_length_min(fpackets)
            flows_dict[cnt]['Fflow Packet Lenght Mean'] = flow_packets_length_mean(fpackets)
            flows_dict[cnt]['Fflow Packet Lenght Sum'] = flow_packets_length_sum(fpackets)
            flows_dict[cnt]['Fflow Packet Lenght Std'] = flow_packets_length_std(fpackets)
            
            # idle features
            flows_dict[cnt]['Down-Up Ratio'] = Get_down_up_ratio(flow)
            flows_dict[cnt]['Idle Min'] = Get_idle_min(flow)
            flows_dict[cnt]['Idle Max'] = Get_idle_max(flow)
            flows_dict[cnt]['Idle Std'] = Get_idle_std(flow)
            flows_dict[cnt]['Idle Mean'] = Get_idle_mean(flow)

            # flows_dict[cnt][''] =
            # flows_dict[cnt][''] =
            # flows_dict[cnt][''] =

            # goes to the next flow
            cnt += 1

        df = pd.DataFrame.from_dict(flows_dict, orient='index')
        df.to_csv('TrafficFlow.csv')
        print('File has been created')


        
