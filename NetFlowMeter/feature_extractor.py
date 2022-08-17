#!/usr/bin/env python3

from datetime import datetime
from .features import *


class FeatureExtractor(object):
    def __init__(self, flows: list, floating_point_unit: str):
        self.__flows = flows
        self.floating_point_unit = floating_point_unit
        self.__features = [
                TotalPayloadBytes(),
                FwdTotalPayloadBytes(),
                BwdTotalPayloadBytes(),
                PayloadBytesMax(),
                PayloadBytesMin(),
                PayloadBytesMean(),
                PayloadBytesStd(),
                FwdPayloadBytesMax(),
                FwdPayloadBytesMin(),
                FwdPayloadBytesMean(),
                FwdPayloadBytesStd(),
                BwdPayloadBytesMax(),
                BwdPayloadBytesMin(),
                BwdPayloadBytesMean(),
                BwdPayloadBytesStd(),
                FwdAvgSegmentSize(),
                BwdAvgSegmentSize(),
                AvgSegmentSize(),
                PacketsCount(),
                FwdPacketsCount(),
                BwdPacketsCount(),
                Duration(),
                ActiveMin(),
                ActiveMax(),
                ActiveMean(),
                ActiveStd(),
                IdleMin(),
                IdleMax(),
                IdleMean(),
                IdleStd(),
                BytesRate(),
                FwdBytesRate(),
                BwdBytesRate(),
                PacketsRate(),
                BwdPacketsRate(),
                FwdPacketsRate(),
                AvgFwdBytesPerBulk(),
                AvgFwdPacketsPerBulk(),
                AvgFwdBulkRate(),
                AvgBwdBytesPerBulk(),
                AvgBwdPacketsPerBulk(),
                AvgBwdBulkRate(),
                FwdBulkStateCount(),
                FwdBulkSizeTotal(),
                FwdBulkPacketCount(),
                FwdBulkDuration(),
                BwdBulkStateCount(),
                BwdBulkSizeTotal(),
                BwdBulkPacketCount(),
                BwdBulkDuration(),
                FINFlagCounts(),
                PSHFlagCounts(),
                URGFlagCounts(),
                ECEFlagCounts(),
                SYNFlagCounts(),
                ACKFlagCounts(),
                CWRFlagCounts(),
                RSTFlagCounts(),
                IAT(),
                PacketsIATMean(),
                PacketsIATStd(),
                PacketsIATMax(),
                PacketsIATMin(),
                PacketsIATSum(),
                FwdIAT(),
                FwdPacketsIATMean(),
                FwdPacketsIATStd(),
                FwdPacketsIATMax(),
                FwdPacketsIATMin(),
                FwdPacketsIATSum(),
                BwdIAT(),
                BwdPacketsIATMean(),
                BwdPacketsIATStd(),
                BwdPacketsIATMax(),
                BwdPacketsIATMin(),
                BwdPacketsIATSum(),
                SubflowFwdPackets(),
                SubflowBwdPackets(),
                SubflowFwdBytes(),
                SubflowBwdBytes(),
            ]


    def execute(self, features_ignore_list: list = []) -> list:
        self.__extracted_data = []
        for flow in self.__flows:
            features_of_flow = {}
            features_of_flow["flow_id"] = flow.get_flow_id()
            features_of_flow["timestamp"] = flow.get_flow_start_time()
            features_of_flow["src_ip"] = flow.get_src_ip()
            features_of_flow["src_port"] = flow.get_src_port()
            features_of_flow["dst_ip"] = flow.get_dst_ip()
            features_of_flow["dst_port"] = flow.get_dst_port()
            features_of_flow["protocol"] = flow.get_protocol()
            for feature in self.__features:
                if feature.name in features_ignore_list:
                    continue
                feature.set_floating_point_unit(self.floating_point_unit)
                features_of_flow[feature.name] = feature.extract(flow)
            self.__extracted_data.append(features_of_flow.copy())
        return self.__extracted_data.copy()
