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
        self.flow_idle = [] #new
        self.flow_active = [] #new
        self.start_active_time = first_packet.get_timestamp() #new
        self.end_active_time = first_packet.get_timestamp() #new
        self.flow_id = str(self.src_ip) + "-" + str(self.dst_ip) + "-" + str(self.src_port) + "-" + str(
            self.dst_port) + "-" + str(self.protocol)
        # self.forwardpackets = []  ##building the forward/backward from the reader##
        # self.backwardpackets = []

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

    # def get_forwardpackets(self):
    # return self.forwardpackets

    # def get_backwardpackets(self):
    # return self.backwardpackets

    def get_forwardpackets(self):
        return [p for p in self.packets if p.is_forward() == True]

    def get_backwardpackets(self):
        return [p for p in self.packets if p.is_forward() == False]

    def get_flow_id(self):
        return self.flow_id
#new
    def update_active_idle(self, current_time, threshold):
        if ((current_time - self.end_active_time) > threshold):
            if((self.end_active_time - self.start_active_time) > 0):
                self.flow_active.append(self.end_active_time - self.start_active_time)
            self.flow_idle.append(current_time - self.end_active_time)
            self.end_active_time = current_time
            self.start_active_time = current_time
        else:
            self.end_active_time = current_time

    def get_down_up_ratio(self):
        if (self.forwardpackets.size() > 0 ):
            return self.backwardpackets.size() / self.forwardpackets.size()
        return 0
    def get_idle_min(self):
        if(len(self.flow_idle) > 0):
            return min(self.flow_idle)
        else:
            return 0
    def get_idle_max(self):
        if(len(self.flow_idle) > 0):
            return max(self.flow_idle)
        else:
            return 0
    def get_idle_std(self):
        if(len(self.flow_idle) > 0):
            return std(self.flow_idle)
        else:
            return 0

    def get_idle_mean(self):
        if(len(self.flow_idle) > 0):
            return sum(self.flow_idle) / len(self.flow_idle)

        else:
            return 0