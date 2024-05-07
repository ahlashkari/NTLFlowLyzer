#!/usr/bin/env python3

import dpkt
import socket
import datetime
from datetime import datetime


class Packet():
    def __init__(self, src_ip="", src_port=0, dst_ip="", dst_port=0, protocol=None, flags=0,
            timestamp=0, forward=True, length=0, payloadbytes=0, header_size=0,
            window_size=0, seq_number=0, ack_number=0):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.__tcp_flags = flags
        self.timestamp = timestamp
        self.forward = forward
        self.length = length
        self.payloadbytes = payloadbytes
        self.header_size = header_size
        self.__segment_size = self.header_size + self.payloadbytes
        self.window_size = window_size
        self.seq_number = seq_number
        self.ack_number = ack_number

    def __len__(self):
        return self.get_length
    
    def __lt__(self, o: object):
        return (self.timestamp <= o.get_timestamp())


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
        return (self.__tcp_flags & dpkt.tcp.TH_FIN)
    
    def has_flagPSH(self):
        return (self.__tcp_flags & dpkt.tcp.TH_PUSH)

    def has_flagURG(self):
        return (self.__tcp_flags & dpkt.tcp.TH_URG)
    
    def has_flagECE(self):
        return (self.__tcp_flags & dpkt.tcp.TH_ECE)
    
    def has_flagSYN(self):
        return (self.__tcp_flags & dpkt.tcp.TH_SYN)
    
    def has_flagACK(self):
        return (self.__tcp_flags & dpkt.tcp.TH_ACK)

    def has_flagCWR(self):
        return (self.__tcp_flags & dpkt.tcp.TH_CWR)
    
    def has_flagRST(self):
        return (self.__tcp_flags & dpkt.tcp.TH_RST)

    def get_seq_number(self) -> int:
        return self.seq_number

    def get_ack_number(self) -> int:
        return self.ack_number

    def is_forward(self):
        return self.forward
    
    def get_timestamp(self):
        return self.timestamp
    
    def get_length(self):
        return self.length

    def get_payloadbytes(self):
        return self.payloadbytes

    def get_header_size(self):
        return self.header_size

    def get_window_size(self):
        return self.window_size

    def get_segment_size(self):
        return self.__segment_size