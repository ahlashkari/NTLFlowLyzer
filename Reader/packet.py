class Packet():
    
    def __init__(self, src_ip, src_port, dst_ip, dst_port, protocol, flags, timestamp, forward=True):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.flags = flags
        self.forward = forward
        self.timestamp = timestamp
        
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
    
    def has_flagFIN(self): 
        return 'F' in self.flags
    
    def has_flagPSH(self):
        return 'P' in self.flags

    def has_flagURG(self):
        return 'U' in self.flags
    
    def has_flagECE(self):
        return 'E' in self.flags
    
    def has_flagSYN(self):
        return 'S' in self.flags
    
    def has_flagACK(self):
        return 'A' in self.flags

    def has_flagCWR(self):
        return 'C' in self.flags
    
    def has_flagRST(self):
        return 'R' in self.flags
    
    def is_forward(self):
        return self.forward
    
    def get_timestamp(self):
        return self.timestamp
        
    
