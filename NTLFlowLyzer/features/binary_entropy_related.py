#!/usr/bin/env python3

from collections import Counter
from statistics import StatisticsError, stdev
from ..network_flow_capturer import Flow
from .feature import Feature
from . import utils
from scipy import stats



class MEAN4Entropy(Feature):
    name = "mean_binary_per4bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,4)
        try:
            mean_binary_per4bytes_entropy = sum(entropy_values) / len(entropy_values)
        except ZeroDivisionError:
            mean_binary_per4bytes_entropy = 0.0
        return mean_binary_per4bytes_entropy
    
class STD4Entropy(Feature):
    name = "std_binary_per4bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,4)
        try:
            std_binary_per4bytes_entropy = stdev(entropy_values)
        except StatisticsError:
            std_binary_per4bytes_entropy = 0
        return std_binary_per4bytes_entropy
    
class SKEWNESS4Entropy(Feature):
    name = "skewness_binary_per4bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,4)
        try:
            skewness_binary_per4bytes_entropy = stats.skew(entropy_values)
        except ZeroDivisionError:
            skewness_binary_per4bytes_entropy = 0.0
        return skewness_binary_per4bytes_entropy
    
class MODE4Entropy(Feature):
    name = "mode_binary_per4bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,4)
        if entropy_values == []:
            mode_binary_per4bytes_entropy = 0.0
        try:
            mode_binary_per4bytes_entropy = Counter(entropy_values).most_common(1)[0][0]
        except IndexError:
            mode_binary_per4bytes_entropy = 0.0
        return mode_binary_per4bytes_entropy
    
class MEDIAN4Entropy(Feature):
    name = "median_binary_per4bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,4)
        if entropy_values == []:
            median_binary_per4bytes_entropy = 0.0
        try:
            median_binary_per4bytes_entropy = Counter(entropy_values).most_common(1)[0][0]
        except IndexError:
            median_binary_per4bytes_entropy = 0.0
        return median_binary_per4bytes_entropy

class COV4Entropy(Feature):
    name = "cov_binary_per4bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,4)
        if entropy_values == []:
            cov_binary_per4bytes_entropy = 0.0        
        try:
            mean_entropy = sum(entropy_values) / len(entropy_values)
        except ZeroDivisionError:
            mean_entropy = 0.0
        try:
            std_dev_entropy = stdev(entropy_values)
        except StatisticsError:
            std_dev_entropy = 0
        try:
            cov_binary_per4bytes_entropy = std_dev_entropy / mean_entropy * 100
        except ZeroDivisionError:
            cov_binary_per4bytes_entropy = 0
        return cov_binary_per4bytes_entropy
    

class MEAN8Entropy(Feature):
    name = "mean_binary_per8bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,8)
        try:
            mean_binary_per8bytes_entropy = sum(entropy_values) / len(entropy_values)
        except ZeroDivisionError:
            mean_binary_per8bytes_entropy = 0.0
        return mean_binary_per8bytes_entropy
    
class STD8Entropy(Feature):
    name = "std_binary_per8bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,8)
        try:
            std_binary_per8bytes_entropy = stdev(entropy_values)
        except StatisticsError:
            std_binary_per8bytes_entropy = 0
        return std_binary_per8bytes_entropy
    
class SKEWNESS8Entropy(Feature):
    name = "skewness_binary_per8bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,8)
        try:
            skewness_binary_per8bytes_entropy = stats.skew(entropy_values)
        except ZeroDivisionError:
            skewness_binary_per8bytes_entropy = 0.0
        return skewness_binary_per8bytes_entropy
    
class MODE8Entropy(Feature):
    name = "mode_binary_per8bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,8)
        if entropy_values == []:
            mode_binary_per8bytes_entropy = 0.0
        try:
            mode_binary_per8bytes_entropy = Counter(entropy_values).most_common(1)[0][0]
        except IndexError:
            mode_binary_per8bytes_entropy = 0.0
        return mode_binary_per8bytes_entropy
    
class MEDIAN8Entropy(Feature):
    name = "median_binary_per8bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,8)
        if entropy_values == []:
            median_binary_per8bytes_entropy = 0.0
        try:
            median_binary_per8bytes_entropy = Counter(entropy_values).most_common(1)[0][0]
        except IndexError:
            median_binary_per8bytes_entropy = 0.0
        return median_binary_per8bytes_entropy

class COV8Entropy(Feature):
    name = "cov_binary_per8bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,8)
        if entropy_values == []:
            cov_binary_per8bytes_entropy = 0.0        
        try:
            mean_entropy = sum(entropy_values) / len(entropy_values)
        except ZeroDivisionError:
            mean_entropy = 0.0
        try:
            std_dev_entropy = stdev(entropy_values)
        except StatisticsError:
            std_dev_entropy = 0
        try:
            cov_binary_per8bytes_entropy = std_dev_entropy / mean_entropy * 100
        except ZeroDivisionError:
            cov_binary_per8bytes_entropy = 0
        return cov_binary_per8bytes_entropy
    

class MEAN16Entropy(Feature):
    name = "mean_binary_per16bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,16)
        try:
            mean_binary_per16bytes_entropy = sum(entropy_values) / len(entropy_values)
        except ZeroDivisionError:
            mean_binary_per16bytes_entropy = 0.0
        return mean_binary_per16bytes_entropy
    
class STD16Entropy(Feature):
    name = "std_binary_per16bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,16)
        try:
            std_binary_per16bytes_entropy = stdev(entropy_values)
        except StatisticsError:
            std_binary_per16bytes_entropy = 0
        return std_binary_per16bytes_entropy
    
class SKEWNESS16Entropy(Feature):
    name = "skewness_binary_per16bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,16)
        try:
            skewness_binary_per16bytes_entropy = stats.skew(entropy_values)
        except ZeroDivisionError:
            skewness_binary_per16bytes_entropy = 0.0
        return skewness_binary_per16bytes_entropy
    
class MODE16Entropy(Feature):
    name = "mode_binary_per16bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,16)
        if entropy_values == []:
            mode_binary_per16bytes_entropy = 0.0
        try:
            mode_binary_per16bytes_entropy = Counter(entropy_values).most_common(1)[0][0]
        except IndexError:
            mode_binary_per16bytes_entropy = 0.0
        return mode_binary_per16bytes_entropy
    
class MEDIAN16Entropy(Feature):
    name = "median_binary_per16bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,16)
        if entropy_values == []:
            median_binary_per16bytes_entropy = 0.0
        try:
            median_binary_per16bytes_entropy = Counter(entropy_values).most_common(1)[0][0]
        except IndexError:
            median_binary_per16bytes_entropy = 0.0
        return median_binary_per16bytes_entropy

class COV16Entropy(Feature):
    name = "cov_binary_per16bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,16)
        if entropy_values == []:
            cov_binary_per16bytes_entropy = 0.0        
        try:
            mean_entropy = sum(entropy_values) / len(entropy_values)
        except ZeroDivisionError:
            mean_entropy = 0.0
        try:
            std_dev_entropy = stdev(entropy_values)
        except StatisticsError:
            std_dev_entropy = 0
        try:
            cov_binary_per16bytes_entropy = std_dev_entropy / mean_entropy * 100
        except ZeroDivisionError:
            cov_binary_per16bytes_entropy = 0
        return cov_binary_per16bytes_entropy


class MEAN32Entropy(Feature):
    name = "mean_binary_per32bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,32)
        try:
            mean_binary_per32bytes_entropy = sum(entropy_values) / len(entropy_values)
        except ZeroDivisionError:
            mean_binary_per32bytes_entropy = 0.0
        return mean_binary_per32bytes_entropy
    
class STD32Entropy(Feature):
    name = "std_binary_per32bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,32)
        try:
            std_binary_per32bytes_entropy = stdev(entropy_values)
        except StatisticsError:
            std_binary_per32bytes_entropy = 0
        return std_binary_per32bytes_entropy
    
class SKEWNESS32Entropy(Feature):
    name = "skewness_binary_per32bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,32)
        try:
            skewness_binary_per32bytes_entropy = stats.skew(entropy_values)
        except ZeroDivisionError:
            skewness_binary_per32bytes_entropy = 0.0
        return skewness_binary_per32bytes_entropy
    
class MODE32Entropy(Feature):
    name = "mode_binary_per32bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,32)
        if entropy_values == []:
            mode_binary_per32bytes_entropy = 0.0
        try:
            mode_binary_per32bytes_entropy = Counter(entropy_values).most_common(1)[0][0]
        except IndexError:
            mode_binary_per32bytes_entropy = 0.0
        return mode_binary_per32bytes_entropy
    
class MEDIAN32Entropy(Feature):
    name = "median_binary_per32bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,32)
        if entropy_values == []:
            median_binary_per32bytes_entropy = 0.0
        try:
            median_binary_per32bytes_entropy = Counter(entropy_values).most_common(1)[0][0]
        except IndexError:
            median_binary_per32bytes_entropy = 0.0
        return median_binary_per32bytes_entropy

class COV32Entropy(Feature):
    name = "cov_binary_per32bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,32)
        if entropy_values == []:
            cov_binary_per32bytes_entropy = 0.0        
        try:
            mean_entropy = sum(entropy_values) / len(entropy_values)
        except ZeroDivisionError:
            mean_entropy = 0.0
        try:
            std_dev_entropy = stdev(entropy_values)
        except StatisticsError:
            std_dev_entropy = 0
        try:
            cov_binary_per32bytes_entropy = std_dev_entropy / mean_entropy * 100
        except ZeroDivisionError:
            cov_binary_per32bytes_entropy = 0
        return cov_binary_per32bytes_entropy
    

class MEAN64Entropy(Feature):
    name = "mean_binary_per64bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,64)
        try:
            mean_binary_per64bytes_entropy = sum(entropy_values) / len(entropy_values)
        except ZeroDivisionError:
            mean_binary_per64bytes_entropy = 0.0
        return mean_binary_per64bytes_entropy
    
class STD64Entropy(Feature):
    name = "std_binary_per64bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,64)
        try:
            std_binary_per64bytes_entropy = stdev(entropy_values)
        except StatisticsError:
            std_binary_per64bytes_entropy = 0
        return std_binary_per64bytes_entropy
    
class SKEWNESS64Entropy(Feature):
    name = "skewness_binary_per64bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,64)
        try:
            skewness_binary_per64bytes_entropy = stats.skew(entropy_values)
        except ZeroDivisionError:
            skewness_binary_per64bytes_entropy = 0.0
        return skewness_binary_per64bytes_entropy
    
class MODE64Entropy(Feature):
    name = "mode_binary_per64bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,64)
        if entropy_values == []:
            mode_binary_per64bytes_entropy = 0.0
        try:
            mode_binary_per64bytes_entropy = Counter(entropy_values).most_common(1)[0][0]
        except IndexError:
            mode_binary_per64bytes_entropy = 0.0
        return mode_binary_per64bytes_entropy
    
class MEDIAN64Entropy(Feature):
    name = "median_binary_per64bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,64)
        if entropy_values == []:
            median_binary_per64bytes_entropy = 0.0
        try:
            median_binary_per64bytes_entropy = Counter(entropy_values).most_common(1)[0][0]
        except IndexError:
            median_binary_per64bytes_entropy = 0.0
        return median_binary_per64bytes_entropy

class COV64Entropy(Feature):
    name = "cov_binary_per64bytes_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        entropy_values = utils.analyze_binary_entropy(data,64)
        if entropy_values == []:
            cov_binary_per64bytes_entropy = 0.0        
        try:
            mean_entropy = sum(entropy_values) / len(entropy_values)
        except ZeroDivisionError:
            mean_entropy = 0.0
        try:
            std_dev_entropy = stdev(entropy_values)
        except StatisticsError:
            std_dev_entropy = 0
        try:
            cov_binary_per64bytes_entropy = std_dev_entropy / mean_entropy * 100
        except ZeroDivisionError:
            cov_binary_per64bytes_entropy = 0
        return cov_binary_per64bytes_entropy
    
    