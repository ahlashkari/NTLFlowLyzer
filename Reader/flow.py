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
        
    
