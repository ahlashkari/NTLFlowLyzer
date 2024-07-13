#!/usr/bin/env python3


import binascii
from ..network_flow_capturer import Flow
from .feature import Feature
import numpy as np
from . import utils

class BIN2GramEntropy(Feature):
    name = "binary_2_gram_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = ''.join(['{:08b}'.format(x) for x in data])
        binary_2_gram_entropy = utils.analyze_ngram_entropy(encoded_data,2)
        return binary_2_gram_entropy
    
class BIN3GramEntropy(Feature):
    name = "binary_3_gram_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = ''.join(['{:08b}'.format(x) for x in data])
        binary_3_gram_entropy = utils.analyze_ngram_entropy(encoded_data,3)
        return binary_3_gram_entropy
    
class BIN4GramEntropy(Feature):
    name = "binary_4_gram_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = ''.join(['{:08b}'.format(x) for x in data])
        binary_4_gram_entropy = utils.analyze_ngram_entropy(encoded_data,4)
        return binary_4_gram_entropy
    
class BIN5GramEntropy(Feature):
    name = "binary_5_gram_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = ''.join(['{:08b}'.format(x) for x in data])
        binary_5_gram_entropy = utils.analyze_ngram_entropy(encoded_data,5)
        return binary_5_gram_entropy
    
class BIN6GramEntropy(Feature):
    name = "binary_6_gram_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = ''.join(['{:08b}'.format(x) for x in data])
        binary_6_gram_entropy = utils.analyze_ngram_entropy(encoded_data,6)
        return binary_6_gram_entropy
    
class BIN7GramEntropy(Feature):
    name = "binary_7_gram_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = ''.join(['{:08b}'.format(x) for x in data])
        binary_7_gram_entropy = utils.analyze_ngram_entropy(encoded_data,7)
        return binary_7_gram_entropy
    
class BIN8GramEntropy(Feature):
    name = "binary_8_gram_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = ''.join(['{:08b}'.format(x) for x in data])
        binary_8_gram_entropy = utils.analyze_ngram_entropy(encoded_data,8)
        return binary_8_gram_entropy
    
class BIN9GramEntropy(Feature):
    name = "binary_9_gram_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = ''.join(['{:08b}'.format(x) for x in data])
        binary_9_gram_entropy = utils.analyze_ngram_entropy(encoded_data,9)
        return binary_9_gram_entropy
    
class BIN10GramEntropy(Feature):
    name = "binary_10_gram_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = ''.join(['{:08b}'.format(x) for x in data])
        binary_10_gram_entropy = utils.analyze_ngram_entropy(encoded_data,10)
        return binary_10_gram_entropy
    
class HEX2GramEntropy(Feature):
    name = "hex_2_gram_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = str(data)
        hex_2_gram_entropy = utils.analyze_ngram_entropy(encoded_data,2)
        return hex_2_gram_entropy
    
class HEX3GramEntropy(Feature):
    name = "hex_3_gram_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = str(data)
        hex_3_gram_entropy = utils.analyze_ngram_entropy(encoded_data,3)
        return hex_3_gram_entropy
    
class HEX4GramEntropy(Feature):
    name = "hex_4_gram_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = str(data)
        hex_4_gram_entropy = utils.analyze_ngram_entropy(encoded_data,4)
        return hex_4_gram_entropy
    
class HEX5GramEntropy(Feature):
    name = "hex_5_gram_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = str(data)
        hex_5_gram_entropy = utils.analyze_ngram_entropy(encoded_data,5)
        return hex_5_gram_entropy
    
class HEX6GramEntropy(Feature):
    name = "hex_6_gram_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = str(data)
        hex_6_gram_entropy = utils.analyze_ngram_entropy(encoded_data,6)
        return hex_6_gram_entropy
    
class HEX7GramEntropy(Feature):
    name = "hex_7gram_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = str(data)
        hex_7_gram_entropy = utils.analyze_ngram_entropy(encoded_data,7)
        return hex_7_gram_entropy
    
class HEX8GramEntropy(Feature):
    name = "hex_8_gram_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = str(data)
        hex_8_gram_entropy = utils.analyze_ngram_entropy(encoded_data,8)
        return hex_8_gram_entropy
    
class HEX9GramEntropy(Feature):
    name = "hex_9_gram_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = str(data)
        hex_9_gram_entropy = utils.analyze_ngram_entropy(encoded_data,9)
        return hex_9_gram_entropy
    
class HEX10GramEntropy(Feature):
    name = "hex_10_gram_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = str(data)
        hex_10_gram_entropy = utils.analyze_ngram_entropy(encoded_data,10)
        return hex_10_gram_entropy
    
class UTF82GramEntropy(Feature):
    name = "utf8_2_gram_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = binascii.hexlify(data).decode('ascii')
        utf8_2_gram_entropy = utils.analyze_ngram_entropy(encoded_data,2)
        return utf8_2_gram_entropy
    
class UTF83GramEntropy(Feature):
    name = "utf8_3_gram_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = binascii.hexlify(data).decode('ascii')
        utf8_3_gram_entropy = utils.analyze_ngram_entropy(encoded_data,3)
        return utf8_3_gram_entropy
    

class UTF84GramEntropy(Feature):
    name = "utf8_4_gram_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = binascii.hexlify(data).decode('ascii')
        utf8_4_gram_entropy = utils.analyze_ngram_entropy(encoded_data,4)
        return utf8_4_gram_entropy
    
class UTF85GramEntropy(Feature):
    name = "utf8_5_gram_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = binascii.hexlify(data).decode('ascii')
        utf8_5_gram_entropy = utils.analyze_ngram_entropy(encoded_data,5)
        return utf8_5_gram_entropy
    
class UTF86GramEntropy(Feature):
    name = "utf8_6_gram_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = binascii.hexlify(data).decode('ascii')
        utf8_6_gram_entropy = utils.analyze_ngram_entropy(encoded_data,6)
        return utf8_6_gram_entropy
    
class UTF87GramEntropy(Feature):
    name = "utf8_7_gram_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = binascii.hexlify(data).decode('ascii')
        utf8_7_gram_entropy = utils.analyze_ngram_entropy(encoded_data,7)
        return utf8_7_gram_entropy
    
class UTF88GramEntropy(Feature):
    name = "utf8_8_gram_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = binascii.hexlify(data).decode('ascii')
        utf8_8_gram_entropy = utils.analyze_ngram_entropy(encoded_data,8)
        return utf8_8_gram_entropy
    
class UTF89GramEntropy(Feature):
    name = "utf8_9_gram_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = binascii.hexlify(data).decode('ascii')
        utf8_9_gram_entropy = utils.analyze_ngram_entropy(encoded_data,9)
        return utf8_9_gram_entropy
    
class UTF810GramEntropy(Feature):
    name = "utf8_10_gram_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = binascii.hexlify(data).decode('ascii')
        utf8_10_gram_entropy = utils.analyze_ngram_entropy(encoded_data,10)
        return utf8_10_gram_entropy
    
