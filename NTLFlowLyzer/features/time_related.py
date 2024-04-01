#!/usr/bin/env python3

from datetime import datetime
import statistics
from enum import Enum
from typing import List
from scipy import stats

from NTLFlowLyzer.network_flow_capturer.packet import Packet
from ..network_flow_capturer import Flow
from .feature import Feature
from . import utils


class Duration(Feature):
    name = "duration"
    def extract(self, flow: Flow) -> float:
        return utils.calculate_flow_duration(flow)


class ActiveMin(Feature):
    name = "active_min"
    def extract(self, flow: Flow) -> float:
        if not flow.get_flow_active():
            return 0
        return min(flow.get_flow_active())


class ActiveMax(Feature):
    name = "active_max"
    def extract(self, flow: Flow) -> float:
        if not flow.get_flow_active():
            return 0
        return max(flow.get_flow_active())


class ActiveMean(Feature):
    name = "active_mean"
    def extract(self, flow: Flow) -> float:
        if not flow.get_flow_active():
            return 0
        return format(statistics.mean(flow.get_flow_active()), self.floating_point_unit)


class ActiveStd(Feature):
    name = "active_std"
    def extract(self, flow: Flow) -> float:
        if not flow.get_flow_active():
            return 0
        return format(statistics.pstdev(flow.get_flow_active()), self.floating_point_unit)


class ActiveMedian(Feature):
    name = "active_median"
    def extract(self, flow: Flow) -> float:
        if not flow.get_flow_active():
            return 0
        return format(statistics.median(flow.get_flow_active()), self.floating_point_unit)


class ActiveSkewness(Feature):
    name = "active_skewness"
    def extract(self, flow: Flow) -> float:
        if not flow.get_flow_active():
            return 0
        return format(float(stats.skew(flow.get_flow_active())), self.floating_point_unit)


class ActiveCoV(Feature):
    name = "active_cov"
    def extract(self, flow: Flow) -> float:
        if not flow.get_flow_active():
            return 0
        return format(stats.variation(flow.get_flow_active()), self.floating_point_unit)


class ActiveMode(Feature):
    name = "active_mode"
    def extract(self, flow: Flow) -> float:
        if not flow.get_flow_active():
            return 0
        return format(float(stats.mode(flow.get_flow_active())[0]), self.floating_point_unit)


class ActiveVariance(Feature):
    name = "active_variance"
    def extract(self, flow: Flow) -> float:
        if not flow.get_flow_active():
            return 0
        return format(statistics.pvariance(flow.get_flow_active()), self.floating_point_unit)


class IdleMin(Feature):
    name = "idle_min"
    def extract(self, flow: Flow) -> float:
        if not flow.get_flow_idle():
            return 0
        return min(flow.get_flow_idle())


class IdleMax(Feature):
    name = "idle_max"
    def extract(self, flow: Flow) -> float:
        if not flow.get_flow_idle():
            return 0
        return max(flow.get_flow_idle())


class IdleMean(Feature):
    name = "idle_mean"
    def extract(self, flow: Flow) -> float:
        if not flow.get_flow_idle():
            return 0
        return format(statistics.mean(flow.get_flow_idle()), self.floating_point_unit)


class IdleStd(Feature):
    name = "idle_std"
    def extract(self, flow: Flow) -> float:
        if not flow.get_flow_idle():
            return 0
        return format(statistics.pstdev(flow.get_flow_idle()), self.floating_point_unit)


class IdleMedian(Feature):
    name = "idle_median"
    def extract(self, flow: Flow) -> float:
        if not flow.get_flow_active():
            return 0
        return format(statistics.median(flow.get_flow_idle()), self.floating_point_unit)


class IdleSkewness(Feature):
    name = "idle_skewness"
    def extract(self, flow: Flow) -> float:
        if not flow.get_flow_active():
            return 0
        return format(float(stats.skew(flow.get_flow_idle())), self.floating_point_unit)


class IdleCoV(Feature):
    name = "idle_cov"
    def extract(self, flow: Flow) -> float:
        if not flow.get_flow_active():
            return 0
        return format(stats.variation(flow.get_flow_idle()), self.floating_point_unit)


class IdleMode(Feature):
    name = "idle_mode"
    def extract(self, flow: Flow) -> float:
        if not flow.get_flow_active():
            return 0
        return format(float(stats.mode(flow.get_flow_idle())[0]), self.floating_point_unit)


class IdleVariance(Feature):
    name = "idle_variance"
    def extract(self, flow: Flow) -> float:
        if not flow.get_flow_active():
            return 0
        return format(statistics.pvariance(flow.get_flow_idle()), self.floating_point_unit)


class PacketsDeltaTimeBase(Feature):
    def __get_packets_delta_time(self, packets: List[Packet]):
        packets_timestamp = [datetime.fromtimestamp(float(packet.get_timestamp())) for packet in packets]
        packets_sorted = sorted(packets_timestamp)
        packets_del_time = [(pkt - pkt_prev).microseconds/1000 for pkt_prev, pkt in zip(packets_sorted[:-1], packets_sorted[1:])]
        return packets_del_time

    def get_receiving_delta(self, flow: Flow) -> list:
        return self.__get_packets_delta_time(flow.get_backwardpackets())

    def get_sending_delta(self, flow: Flow) -> list:
        return self.__get_packets_delta_time(flow.get_forwardpackets())

    def get_all_delta(self, flow: Flow) -> list:
        return self.__get_packets_delta_time(flow.get_packets())


class HandshakingStates(Enum):
    Ideal = 0
    CLIENT_SENT_HANDSHAKE_REQUEST = 1
    SERVER_ACKNWOLEDGED_CLIENT_HANDSHAKE_REQUEST = 2
    END_OF_HANDSHAKING = 3


class Handshake(Feature):
    name = "handshake"
    delta = None
    duration = None

    def extract_data_from_handshaking_process(self, flow: Flow):
        if flow.get_protocol() != "TCP":
            self.delta = "not a tcp connection"
            self.duration = "not a tcp connection"
            return

        packets = flow.get_packets()
        last_handshake_packet_time = 0
        first_handshake_packet_time = 0
        first_not_handshake_packet_time = 0
        STATE = HandshakingStates.Ideal
        self.final_state = STATE
        seq_number = 0
        ack_number = 0
        for packet in packets:
            if STATE == HandshakingStates.END_OF_HANDSHAKING:
                if first_not_handshake_packet_time == 0:
                    first_not_handshake_packet_time = packet.get_timestamp()
                self.delta = format(first_not_handshake_packet_time - last_handshake_packet_time,
                        self.floating_point_unit)
                self.duration = format(last_handshake_packet_time - first_handshake_packet_time,
                        self.floating_point_unit)
                return

            if STATE == HandshakingStates.Ideal and packet.has_flagSYN():
                first_handshake_packet_time = packet.get_timestamp()
                seq_number = packet.get_seq_number()
                STATE = HandshakingStates.CLIENT_SENT_HANDSHAKE_REQUEST
                self.final_state = STATE

            elif STATE == HandshakingStates.CLIENT_SENT_HANDSHAKE_REQUEST \
                    and packet.has_flagSYN() \
                    and packet.has_flagACK() and seq_number == packet.get_ack_number() - 1:
                seq_number = packet.get_seq_number()
                ack_number = packet.get_ack_number()
                STATE = HandshakingStates.SERVER_ACKNWOLEDGED_CLIENT_HANDSHAKE_REQUEST
                self.final_state = STATE

            elif STATE == HandshakingStates.SERVER_ACKNWOLEDGED_CLIENT_HANDSHAKE_REQUEST \
                    and packet.has_flagACK() and seq_number == packet.get_ack_number() - 1 \
                    and ack_number == packet.get_seq_number():
                last_handshake_packet_time = packet.get_timestamp()
                STATE = HandshakingStates.END_OF_HANDSHAKING
                self.final_state = STATE

            elif first_not_handshake_packet_time == 0:
                first_not_handshake_packet_time = packet.get_timestamp()

        self.delta = "not a complete handshake"
        self.duration = "not a complete handshake"

    def extract(self, flow: Flow) -> float:
        pass


class DeltaStart(Handshake):
    name = "delta_start"
    def extract(self, flow: Flow) -> float:
        self.extract_data_from_handshaking_process(flow)
        return self.delta


class HandshakeDuration(Handshake):
    name = "handshake_duration"
    def extract(self, flow: Flow) -> float:
        self.extract_data_from_handshaking_process(flow)
        return self.duration


class HandshakeState(Handshake):
    name = "handshake_state"
    def extract(self, flow: Flow) -> float:
        self.extract_data_from_handshaking_process(flow)
        return self.final_state.value


class PacketsDeltaTimeMin(PacketsDeltaTimeBase):
    name = "min_bwd_packets_delta_time"
    def extract(self, flow: Flow) -> float:
        packets_del_time = super().get_all_delta(flow)
        if len(packets_del_time) > 0:
            return format(min(packets_del_time), self.floating_point_unit)
        return 0


class PacketsDeltaTimeMax(PacketsDeltaTimeBase):
    name = "max_bwd_packets_delta_time"
    def extract(self, flow: Flow) -> float:
        packets_del_time = super().get_all_delta(flow)
        if len(packets_del_time) > 0:
            return format(max(packets_del_time), self.floating_point_unit)
        return 0


class PacketsDeltaTimeMean(PacketsDeltaTimeBase):
    name = "mean_packets_delta_time"
    def extract(self, flow: Flow) -> float:
        packets_del_time = super().get_all_delta(flow)
        if len(packets_del_time) > 0:
            return format(statistics.mean(packets_del_time), self.floating_point_unit)
        return 0


class PacketsDeltaTimeMode(PacketsDeltaTimeBase):
    name = "mode_packets_delta_time"
    def extract(self, flow: Flow) -> float:
        packets_del_time = super().get_all_delta(flow)
        if len(packets_del_time) > 0:
            return format(float(stats.mode(packets_del_time)[0]), self.floating_point_unit)
        return 0


class PacketsDeltaTimeVariance(PacketsDeltaTimeBase):
    name = "variance_packets_delta_time"
    def extract(self, flow: Flow) -> float:
        packets_del_time = super().get_all_delta(flow)
        if len(packets_del_time) > 0:
            return format(statistics.pvariance(packets_del_time), self.floating_point_unit)
        return 0


class PacketsDeltaTimeStd(PacketsDeltaTimeBase):
    name = "std_packets_delta_time"
    def extract(self, flow: Flow) -> float:
        packets_del_time = super().get_all_delta(flow)
        if len(packets_del_time) > 0:
            return format(statistics.pstdev(packets_del_time), self.floating_point_unit)
        return 0


class PacketsDeltaTimeMedian(PacketsDeltaTimeBase):
    name = "median_packets_delta_time"
    def extract(self, flow: Flow) -> float:
        packets_del_time = super().get_all_delta(flow)
        if len(packets_del_time) > 0:
            return format(statistics.median(packets_del_time), self.floating_point_unit)
        return 0


class PacketsDeltaTimeSkewness(PacketsDeltaTimeBase):
    name = "skewness_packets_delta_time"
    def extract(self, flow: Flow) -> float:
        packets_del_time = super().get_all_delta(flow)
        if len(packets_del_time) > 0:
            return format(float(stats.skew(packets_del_time)), self.floating_point_unit)
        return 0


class PacketsDeltaTimeCoV(PacketsDeltaTimeBase):
    name = "cov_packets_delta_time"
    def extract(self, flow: Flow) -> float:
        packets_del_time = super().get_all_delta(flow)
        if len(packets_del_time) > 0:
            return format(stats.variation(packets_del_time), self.floating_point_unit)
        return 0


class BwdPacketsDeltaTimeMin(PacketsDeltaTimeBase):
    name = "min_bwd_packets_delta_time"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_time = super().get_receiving_delta(flow)
        if len(receiving_packets_del_time) > 0:
            return format(min(receiving_packets_del_time), self.floating_point_unit)
        return 0


class BwdPacketsDeltaTimeMax(PacketsDeltaTimeBase):
    name = "max_bwd_packets_delta_time"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_time = super().get_receiving_delta(flow)
        if len(receiving_packets_del_time) > 0:
            return format(max(receiving_packets_del_time), self.floating_point_unit)
        return 0


class BwdPacketsDeltaTimeMean(PacketsDeltaTimeBase):
    name = "mean_bwd_packets_delta_time"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_time = super().get_receiving_delta(flow)
        if len(receiving_packets_del_time) > 0:
            return format(statistics.mean(receiving_packets_del_time), self.floating_point_unit)
        return 0


class BwdPacketsDeltaTimeMode(PacketsDeltaTimeBase):
    name = "mode_bwd_packets_delta_time"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_time = super().get_receiving_delta(flow)
        if len(receiving_packets_del_time) > 0:
            return format(float(stats.mode(receiving_packets_del_time)[0]), self.floating_point_unit)
        return 0


class BwdPacketsDeltaTimeVariance(PacketsDeltaTimeBase):
    name = "variance_bwd_packets_delta_time"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_time = super().get_receiving_delta(flow)
        if len(receiving_packets_del_time) > 0:
            return format(statistics.pvariance(receiving_packets_del_time), self.floating_point_unit)
        return 0


class BwdPacketsDeltaTimeStd(PacketsDeltaTimeBase):
    name = "std_bwd_packets_delta_time"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_time = super().get_receiving_delta(flow)
        if len(receiving_packets_del_time) > 0:
            return format(statistics.pstdev(receiving_packets_del_time), self.floating_point_unit)
        return 0


class BwdPacketsDeltaTimeMedian(PacketsDeltaTimeBase):
    name = "median_bwd_packets_delta_time"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_time = super().get_receiving_delta(flow)
        if len(receiving_packets_del_time) > 0:
            return format(statistics.median(receiving_packets_del_time), self.floating_point_unit)
        return 0


class BwdPacketsDeltaTimeSkewness(PacketsDeltaTimeBase):
    name = "skewness_bwd_packets_delta_time"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_time = super().get_receiving_delta(flow)
        if len(receiving_packets_del_time) > 0:
            return format(float(stats.skew(receiving_packets_del_time)), self.floating_point_unit)
        return 0


class BwdPacketsDeltaTimeCoV(PacketsDeltaTimeBase):
    name = "cov_bwd_packets_delta_time"
    def extract(self, flow: Flow) -> float:
        receiving_packets_del_time = super().get_receiving_delta(flow)
        if len(receiving_packets_del_time) > 0:
            return format(stats.variation(receiving_packets_del_time), self.floating_point_unit)
        return 0


class FwdPacketsDeltaTimeMin(PacketsDeltaTimeBase):
    name = "min_fwd_packets_delta_time"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_time = super().get_sending_delta(flow)
        if len(sending_packets_del_time) > 0:
            return format(min(sending_packets_del_time), self.floating_point_unit)
        return 0


class FwdPacketsDeltaTimeMax(PacketsDeltaTimeBase):
    name = "max_fwd_packets_delta_time"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_time = super().get_sending_delta(flow)
        if len(sending_packets_del_time) > 0:
            return format(max(sending_packets_del_time), self.floating_point_unit)
        return 0


class FwdPacketsDeltaTimeMean(PacketsDeltaTimeBase):
    name = "mean_fwd_packets_delta_time"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_time = super().get_sending_delta(flow)
        if len(sending_packets_del_time) > 0:
            return format(statistics.mean(sending_packets_del_time), self.floating_point_unit)
        return 0


class FwdPacketsDeltaTimeMode(PacketsDeltaTimeBase):
    name = "mode_fwd_packets_delta_time"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_time = super().get_sending_delta(flow)
        if len(sending_packets_del_time) > 0:
            return format(float(stats.mode(sending_packets_del_time)[0]), self.floating_point_unit)
        return 0


class FwdPacketsDeltaTimeVariance(PacketsDeltaTimeBase):
    name = "variance_fwd_packets_delta_time"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_time = super().get_sending_delta(flow)
        if len(sending_packets_del_time) > 0:
            return format(statistics.pvariance(sending_packets_del_time), self.floating_point_unit)
        return 0


class FwdPacketsDeltaTimeStd(PacketsDeltaTimeBase):
    name = "std_fwd_packets_delta_time"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_time = super().get_sending_delta(flow)
        if len(sending_packets_del_time) > 0:
            return format(statistics.pstdev(sending_packets_del_time), self.floating_point_unit)
        return 0


class FwdPacketsDeltaTimeMedian(PacketsDeltaTimeBase):
    name = "median_fwd_packets_delta_time"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_time = super().get_sending_delta(flow)
        if len(sending_packets_del_time) > 0:
            return format(statistics.median(sending_packets_del_time), self.floating_point_unit)
        return 0


class FwdPacketsDeltaTimeSkewness(PacketsDeltaTimeBase):
    name = "skewness_fwd_packets_delta_time"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_time = super().get_sending_delta(flow)
        if len(sending_packets_del_time) > 0:
            return format(float(stats.skew(sending_packets_del_time)), self.floating_point_unit)
        return 0


class FwdPacketsDeltaTimeCoV(PacketsDeltaTimeBase):
    name = "cov_fwd_packets_delta_time"
    def extract(self, flow: Flow) -> float:
        sending_packets_del_time = super().get_sending_delta(flow)
        if len(sending_packets_del_time) > 0:
            return format(stats.variation(sending_packets_del_time), self.floating_point_unit)
        return 0
