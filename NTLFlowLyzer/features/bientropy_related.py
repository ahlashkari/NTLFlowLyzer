#!/usr/bin/env python3

from bitstring import Bits
from ..network_flow_capturer import Flow
from .feature import Feature
from . import utils

class Bi16Entropy(Feature):
    name = "mean_per16bytes_bientropy"
    def extract(self, flow: Flow) -> int:
        seq_len = 16 
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        data_bits = Bits(bytes=data)
        substrings = []
        for i in range(0, len(data_bits) - seq_len + 1):
            substrings.append(data_bits[i:i + seq_len])
        try:
            tbien_values = [utils.tbien(substring) for substring in substrings]
            mean_per16bytes_bientropy = sum(tbien_values) / len(tbien_values)
        except ZeroDivisionError:
            mean_per16bytes_bientropy = 0
        return mean_per16bytes_bientropy
    
class Bi32Entropy(Feature):
    name = "mean_per32bytes_bientropy"
    def extract(self, flow: Flow) -> int:
        seq_len = 32 
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        data_bits = Bits(bytes=data)
        substrings = []
        for i in range(0, len(data_bits) - seq_len + 1):
            substrings.append(data_bits[i:i + seq_len])
        try:
            tbien_values = [utils.tbien(substring) for substring in substrings]
            mean_per32bytes_bientropy = sum(tbien_values) / len(tbien_values)
        except ZeroDivisionError:
            mean_per32bytes_bientropy = 0
        return mean_per32bytes_bientropy