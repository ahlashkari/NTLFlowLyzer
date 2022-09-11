#!/usr/bin/env python3

from datetime import datetime
from .features import *


class FeatureExtractor(object):
    def __init__(self, flows: list, floating_point_unit: str):
        self.__flows = flows
        self.floating_point_unit = floating_point_unit
        self.__features = [
                Duration(),
                PacketsCount(),
                FwdPacketsCount(),
                BwdPacketsCount(),
                TotalPayloadBytes(),
                FwdTotalPayloadBytes(),
                BwdTotalPayloadBytes(),
                PayloadBytesMax(),
                PayloadBytesMin(),
                PayloadBytesMean(),
                PayloadBytesStd(),
                PayloadBytesVariance(),
                FwdPayloadBytesMax(),
                FwdPayloadBytesMin(),
                FwdPayloadBytesMean(),
                FwdPayloadBytesStd(),
                FwdPayloadBytesVariance(),
                BwdPayloadBytesMax(),
                BwdPayloadBytesMin(),
                BwdPayloadBytesMean(),
                BwdPayloadBytesStd(),
                BwdPayloadBytesVariance(),
                TotalHeaderBytes(),
                MaxHeaderBytes(),
                MinHeaderBytes(),
                MeanHeaderBytes(),
                StdHeaderBytes(),
                FwdTotalHeaderBytes(),
                FwdMaxHeaderBytes(),
                FwdMinHeaderBytes(),
                FwdMeanHeaderBytes(),
                FwdStdHeaderBytes(),
                BwdTotalHeaderBytes(),
                BwdMaxHeaderBytes(),
                BwdMinHeaderBytes(),
                BwdMeanHeaderBytes(),
                BwdStdHeaderBytes(),
                FwdAvgSegmentSize(),
                BwdAvgSegmentSize(),
                AvgSegmentSize(),
                FwdInitWinBytes(),
                BwdInitWinBytes(),
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
                DownUpRate(),
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
                FwdFINFlagCounts(),
                FwdPSHFlagCounts(),
                FwdURGFlagCounts(),
                FwdECEFlagCounts(),
                FwdSYNFlagCounts(),
                FwdACKFlagCounts(),
                FwdCWRFlagCounts(),
                FwdRSTFlagCounts(),
                BwdFINFlagCounts(),
                BwdPSHFlagCounts(),
                BwdURGFlagCounts(),
                BwdECEFlagCounts(),
                BwdSYNFlagCounts(),
                BwdACKFlagCounts(),
                BwdCWRFlagCounts(),
                BwdRSTFlagCounts(),
                PacketsIATMean(),
                PacketsIATStd(),
                PacketsIATMax(),
                PacketsIATMin(),
                PacketsIATSum(),
                FwdPacketsIATMean(),
                FwdPacketsIATStd(),
                FwdPacketsIATMax(),
                FwdPacketsIATMin(),
                FwdPacketsIATSum(),
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
            features_of_flow["flow_id"] = str(flow)
            features_of_flow["timestamp"] = str(datetime.fromtimestamp(float(flow.flow_start_time)))
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
