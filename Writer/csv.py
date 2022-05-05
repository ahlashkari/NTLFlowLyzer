class csv_writer:
        
    def create_csv(self, flows_list):
        flows_dict = {}
        cnt = 0
        column_names=['FlowId' , 'SourceIP', 'DestinationIP', 'SourcePort', 'DestinationPort', 'FlowProtocol']
        for flow in flows_list:
            flows_dict[cnt] = [flow.get_flow_id(), flow.get_src_ip(), flow.get_dst_ip(), flow.get_src_port(), flow.get_dst_port(), flow.get_protocol()]
            cnt+=1
        df = pd.DataFrame.from_dict(flows_dict, orient='index', columns=column_names)
        df.to_csv('TrafficFlow.csv')
        print('File has been created')
        
