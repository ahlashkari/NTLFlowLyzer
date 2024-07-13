#!/usr/bin/env python3

from collections import Counter
from statistics import StatisticsError, stdev
from scipy import stats
from ..network_flow_capturer import Flow
from .feature import Feature
from .utils import * 

class MEANMutualInformation(Feature):
    name = "mean_per64bytes_mutual_information"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        mi_values = analyze_mutual_information(data)
        mean_per64bytes_mutual_information = sum(mi_values) / len(mi_values)
        return mean_per64bytes_mutual_information
    
class STDMutualInformation(Feature):
    name = "std_per64bytes_mutual_information"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        mi_values = analyze_mutual_information(data)
        try:
            std_per64bytes_mutual_information = stdev(mi_values)
        except StatisticsError:
            std_per64bytes_mutual_information = 0
        return std_per64bytes_mutual_information
    
class SKEWNESSMutualInformation(Feature):
    name = "skewness_per64bytes_mutual_information"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        mi_values = analyze_mutual_information(data)
        skewness_per64bytes_mutual_information = stats.skew(mi_values)
        return skewness_per64bytes_mutual_information
    
class MODEMutualInformation(Feature):
    name = "mode_per64bytes_mutual_information"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        mi_values = analyze_mutual_information(data)
        mode_per64bytes_mutual_information = Counter(mi_values).most_common(1)[0][0]
        return mode_per64bytes_mutual_information
    
class MEDIANMutualInformation(Feature):
    name = "median_per64bytes_mutual_information"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        mi_values = analyze_mutual_information(data)
        median_per64bytes_mutual_information = sorted(mi_values)[len(mi_values) // 2]
        return median_per64bytes_mutual_information
    
class COVMutualInformation(Feature):
    name = "cov_per64bytes_mutual_information"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        mi_values = analyze_mutual_information(data)
        mean_mi = sum(mi_values) / len(mi_values)
        try:
            std_dev_mi = stdev(mi_values)
        except StatisticsError:
            std_dev_mi = 0
        try:
            mean_per64bytes_mutual_information = std_dev_mi / mean_mi * 100
        except ZeroDivisionError:
            mean_per64bytes_mutual_information = 0
        return mean_per64bytes_mutual_information