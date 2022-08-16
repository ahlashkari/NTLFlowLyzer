#!/usr/bin/env python3

from datetime import datetime


class Flow(object):
    
    def __init__(self,packet):
        self.src_ip = packet.get_src_ip()
        self.dst_ip = packet.get_dst_ip()
        self.src_port = packet.get_src_port()
        self.dst_port = packet.get_dst_port()
        self.protocol = packet.get_protocol()
        self.first_packet = packet  # will we need it?
        self.flow_start_time = packet.get_timestamp()
        self.flow_last_seen = packet.get_timestamp()
        self.packets = []
        self.sflastts = -1
        self.sfcount = 0
        self.flow_active = []
        self.flow_idle = []
        self.start_active_time = packet.get_timestamp()
        self.end_active_time = packet.get_timestamp()
        self.flow_id = str(self.src_ip) + "_" + str(self.src_port) + "_" + str(self.dst_ip) + "_" + str(
            self.dst_port) + "_" + str(self.protocol) + "_" + str(
            datetime.utcfromtimestamp(float(self.flow_start_time)))

        ###bulk features##
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
        ##end bulk features##

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

    def get_forwardpackets(self):
        return [p for p in self.packets if p.is_forward() == True]

    def get_backwardpackets(self):
        return [p for p in self.packets if p.is_forward() == False]

    def get_flow_id(self):
        return self.flow_id

    def get_timestamp(self) :
        return self.flow_last_seen

    def total_packets_payloadbytes(self):
        sum_payloads=0
        for packet in self.packets:
            sum_payloads+= packet.get_payloadbytes()
        # print("total payload is",sum_payloads)
        return sum_payloads

    def update_subflow(self, packet_time):
        if self.sflastts == -1:
            self.sflastts = packet_time
        if packet_time - self.sflastts > 1:
            self.sfcount += 1
        self.sflastts = packet_time

    def get_subflow_count(self):
        return self.sfcount

    def updateFlowBulk(self, packet):  #####
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
            self.fbulkStartHelper = packet.get_timestamp()
            self.fbulkPacketCountHelper = 1
            self.fbulkSizeHelper = size
            self.flastBulkTS = packet.get_timestamp()
        ##possible bulk
        else:
            if (packet.get_timestamp() - self.flastBulkTS) > 1:
                self.fbulkStartHelper = packet.get_timestamp()
                self.flastBulkTS = packet.get_timestamp()
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
                    self.fbulkDuration += packet.get_timestamp()- self.fbulkStartHelper
                else:
                    if self.fbulkPacketCountHelper > 4:
                        self.fbulkPacketCount += 1
                        self.fbulkSizeTotal += size
                        self.fbulkDuration += packet.get_timestamp() - self.flastBulkTS
                self.flastBulkTS = packet.get_timestamp()

    def updateBackwardBulk(self, packet, tsOflastBulkInOther):
        size = packet.get_payloadbytes()
        if tsOflastBulkInOther > self.bbulkStartHelper:
            self.bbulkStartHelper = 0
        if size <= 0:
            return

        if self.bbulkStartHelper == 0:
            self.bbulkStartHelper = packet.get_timestamp()
            self.bbulkPacketCountHelper = 1
            self.bbulkSizeHelper = size
            self.blastBulkTS = packet.get_timestamp()
        ##possible bulk
        else:
            if (packet.get_timestamp() - self.flastBulkTS) > 1:
                self.bbulkStartHelper = packet.get_timestamp()
                self.bblastBulkTS = packet.get_timestamp()
                self.bbulkPacketCountHelper = 1
                self.bbulkSizeHelper = size
            else:  # Add to bulk
                self.bbulkPacketCountHelper += 1
                self.bbulkSizeHelper += size
                # New bulk
                if self.bbulkPacketCountHelper == 4:
                    self.bbulkStateCount += 1
                    self.bbulkPacketCount += self.bbulkPacketCountHelper
                    self.bbulkSizeTotal += self.bbulkSizeHelper
                    self.bbulkDuration += packet.get_timestamp() - self.bbulkStartHelper
                else:
                    if self.bbulkPacketCountHelper > 4:
                        self.bbulkPacketCount += 1
                        self.bbulkSizeTotal += size
                        self.bbulkDuration += packet.get_timestamp() - self.blastBulkTS
                self.blastBulkTS = packet.get_timestamp()

    def fBulkStateCount(self):
        return self.fbulkStateCount

    def fBulkSizeTotal(self):
        return self.fbulkSizeTotal

    def fBulkPacketCount(self):
        return self.fbulkPacketCount

    def fBulkDuration(self):
        return self.fbulkDuration

    def bBulkStateCount(self):
        return self.bbulkStateCount

    def bBulkSizeTotal(self):
        return self.bbulkSizeTotal

    def bBulkPacketCount(self):
        return self.bbulkPacketCount

    def bBulkDuration(self):
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
        time = packet.get_timestamp()
        self.packets.append(packet)
        self.flow_last_seen = time
        self.update_active_idle_time(time)
        self.update_subflow(time)
        self.updateFlowBulk(packet)
