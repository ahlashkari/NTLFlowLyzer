class Flow(object):
    
    def __init__(self, packet):
        self.src_ip = packet.get_src_ip()
        self.dst_ip = packet.get_dst_ip()
        self.src_port = packet.get_src_port()
        self.dst_port = packet.get_dst_port()
        self.protocol = packet.get_protocol()
        self.packets = []
        
    def first_packet(self, packet):
        self.first_packet = packet

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
