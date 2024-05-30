#!/usr/bin/env python3

import datetime
from datetime import datetime
from typing import List
from .packet import Packet


class Flow(object):    
    def __init__(self, packet, activity_timeout):
        self.src_ip = packet.get_src_ip()
        self.dst_ip = packet.get_dst_ip()
        self.src_port = packet.get_src_port()
        self.dst_port = packet.get_dst_port()
        self.protocol = packet.get_protocol()
        self.__activity_timeout = activity_timeout
        self.flow_start_time = float(packet.get_timestamp())
        self.flow_last_seen = float(packet.get_timestamp())
        self.packets = []
        self.sflastts = -1
        self.sfcount = 0
        self.flow_active = []
        self.flow_idle = []
        self.start_active_time = float(packet.get_timestamp())
        self.end_active_time = float(packet.get_timestamp())

        self.__number_of_fwd_fin_flags = 0
        self.__number_of_bwd_fin_flags = 0

        self.__has_rst_flag = False

        self.fbulkDuration = 0
        self.fbulkPacketCount = 0
        self.fbulkSizeTotal = 0
        self.fbulkStateCount = 0
        self.fbulkPacketCountHelper = 0
        self.fbulkStartHelper = 0
        self.fbulkSizeHelper = 0
        self.flastBulkTS = 0
        self.bbulkDuration = 0
        self.bbulkPacketCount = 0
        self.bbulkSizeTotal = 0
        self.bbulkStateCount = 0
        self.bbulkPacketCountHelper = 0
        self.bbulkStartHelper = 0
        self.bbulkSizeHelper = 0
        self.blastBulkTS = 0

    def __str__(self):
        return "_".join([str(self.src_ip), str(self.src_port), str(self.dst_ip), str(self.dst_port),
                         str(self.protocol), str(datetime.fromtimestamp(float(self.flow_start_time)))])

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

    def get_packets(self) -> List[Packet]:
        return self.packets

    def get_flow_start_time(self):
        return self.flow_start_time

    def get_flow_last_seen(self):
        return self.packets[-1].get_timestamp()

    def get_forwardpackets(self) -> List[Packet]:
        return [packet for packet in self.packets if packet.is_forward()]

    def get_backwardpackets(self) -> List[Packet]:
        return [packet for packet in self.packets if not packet.is_forward()]

    def get_timestamp(self):
        return self.flow_start_time

    def total_packets_payloadbytes(self):
        sum_payloads=0
        for packet in self.packets:
            sum_payloads += packet.get_payloadbytes()
        return sum_payloads

    def update_subflow(self, packet_time):
        if self.sflastts == -1:
            self.sflastts = packet_time
        if packet_time - self.sflastts > 1:
            self.sfcount += 1
        self.sflastts = packet_time

    def get_subflow_count(self):
        return self.sfcount

    def updateFlowBulk(self, packet):
        if packet.is_forward():
            self.updateForwardBulk(packet, self.blastBulkTS)
        else:
            self.updateBackwardBulk(packet, self.flastBulkTS)

    def updateForwardBulk(self, packet, tsOflastBulkInOther):
        size = packet.get_payloadbytes()
        if tsOflastBulkInOther > self.fbulkStartHelper:
            self.fbulkStartHelper=0
        if size <= 0:
            return

        if self.fbulkStartHelper == 0:
            self.fbulkStartHelper = float(packet.get_timestamp())
            self.fbulkPacketCountHelper = 1
            self.fbulkSizeHelper = size
            self.flastBulkTS = float(packet.get_timestamp())
        # Possible bulk
        else:
            if (float(packet.get_timestamp()) - self.flastBulkTS) > 1:
                self.fbulkStartHelper = float(packet.get_timestamp())
                self.flastBulkTS = float(packet.get_timestamp())
                self.fbulkPacketCountHelper = 1
                self.fbulkSizeHelper = size
            else:  # Add to bulk
                self.fbulkPacketCountHelper += 1
                self.fbulkSizeHelper += size
                # New bulk
                if self.fbulkPacketCountHelper == 4:
                    self.fbulkStateCount += 1
                    self.fbulkPacketCount += self.fbulkPacketCountHelper
                    self.fbulkSizeTotal += self.fbulkSizeHelper
                    self.fbulkDuration += float(packet.get_timestamp())- self.fbulkStartHelper
                else:
                    if self.fbulkPacketCountHelper > 4:
                        self.fbulkPacketCount += 1
                        self.fbulkSizeTotal += size
                        self.fbulkDuration += float(packet.get_timestamp()) - self.flastBulkTS
                self.flastBulkTS = float(packet.get_timestamp())

    def updateBackwardBulk(self, packet, tsOflastBulkInOther):
        size = packet.get_payloadbytes()
        if tsOflastBulkInOther > self.bbulkStartHelper:
            self.bbulkStartHelper = 0
        if size <= 0:
            return

        if self.bbulkStartHelper == 0:
            self.bbulkStartHelper = float(packet.get_timestamp())
            self.bbulkPacketCountHelper = 1
            self.bbulkSizeHelper = size
            self.blastBulkTS = float(packet.get_timestamp())
        # Possible bulk
        else:
            if (float(packet.get_timestamp()) - self.flastBulkTS) > 1:
                self.bbulkStartHelper = float(packet.get_timestamp())
                self.bblastBulkTS = float(packet.get_timestamp())
                self.bbulkPacketCountHelper = 1
                self.bbulkSizeHelper = size
            else: # Add to bulk
                self.bbulkPacketCountHelper += 1
                self.bbulkSizeHelper += size
                # New bulk
                if self.bbulkPacketCountHelper == 4:
                    self.bbulkStateCount += 1
                    self.bbulkPacketCount += self.bbulkPacketCountHelper
                    self.bbulkSizeTotal += self.bbulkSizeHelper
                    self.bbulkDuration += float(packet.get_timestamp()) - self.bbulkStartHelper
                else:
                    if self.bbulkPacketCountHelper > 4:
                        self.bbulkPacketCount += 1
                        self.bbulkSizeTotal += size
                        self.bbulkDuration += float(packet.get_timestamp()) - self.blastBulkTS
                self.blastBulkTS = float(packet.get_timestamp())

    def get_fBulkStateCount(self):
        return self.fbulkStateCount

    def get_fBulkSizeTotal(self):
        return self.fbulkSizeTotal

    def get_fBulkPacketCount(self):
        return self.fbulkPacketCount

    def get_fBulkDuration(self):
        return self.fbulkDuration

    def get_bBulkStateCount(self):
        return self.bbulkStateCount

    def get_bBulkSizeTotal(self):
        return self.bbulkSizeTotal

    def get_bBulkPacketCount(self):
        return self.bbulkPacketCount

    def get_bBulkDuration(self):
        return self.bbulkDuration

    def update_active_idle_time(self, current_time, active_thr=100):
        if current_time - self.end_active_time > active_thr:
            if self.end_active_time - self.start_active_time > 0:
                self.flow_active.append(self.start_active_time - self.end_active_time)
            self.flow_idle.append(current_time - self.end_active_time)
            self.start_active_time = current_time
        self.end_active_time = current_time

    def get_flow_idle(self):
        return self.flow_idle

    def get_flow_active(self):
        return self.flow_active

    def add_packet(self, packet):
        time = float(packet.get_timestamp())
        self.packets.append(packet)
        self.flow_last_seen = time
        self.update_active_idle_time(time)
        self.update_subflow(time)
        self.updateFlowBulk(packet)

        if packet.has_flagFIN():
            if packet.is_forward():
                self.__number_of_fwd_fin_flags += 1
            else:
                self.__number_of_bwd_fin_flags += 1
                
        if packet.has_flagRST():
            self.__has_rst_flag = True

    def has_two_FIN_flags(self):
        if self.__number_of_fwd_fin_flags >= 1 and self.__number_of_bwd_fin_flags >= 1:
            return True
        return False

    def has_flagRST(self):
        return self.__has_rst_flag

    def actvity_timeout(self, packet: Packet):
        active_time = float(packet.get_timestamp()) - float(self.get_flow_last_seen())
        if active_time > self.__activity_timeout:
            return True
        return False

