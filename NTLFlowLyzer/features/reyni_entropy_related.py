#!/usr/bin/env python3

import binascii
from collections import Counter
from ..network_flow_capturer import Flow
from .feature import Feature
import numpy as np
from . import utils

class BINMinEntropy(Feature):
    name = "bin_min_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = ''.join(['{:08b}'.format(x) for x in data])
        counts = Counter(encoded_data)
        p = [count / len(encoded_data) for count in counts.values() ]
        max_p = max(p, default=0)
        bin_min_entropy = -np.log2(max_p)
        return bin_min_entropy

class HEXMinEntropy(Feature):
    name = "hex_min_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = str(data)
        counts = Counter(encoded_data)
        p = [count / len(encoded_data) for count in counts.values() ]
        max_p = max(p, default=0)
        hex_min_entropy = -np.log2(max_p)
        return hex_min_entropy
    
class UTF8MinEntropy(Feature):
    name = "utf8_min_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = binascii.hexlify(data).decode('ascii')
        counts = Counter(encoded_data)
        p = [count / len(encoded_data) for count in counts.values() ]
        max_p = max(p, default=0)
        utf8_min_entropy = -np.log2(max_p)
        return utf8_min_entropy
    
    
class UTF84MaxEntropy(Feature):
    name = "utf-8_per4bytes_max_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 4
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = binascii.hexlify(data).decode('ascii')
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        utf8_per4bytes_max_entropy = utils.renyi_entropy(b''.join(chunks), alpha=0) 
        return utf8_per4bytes_max_entropy
    
class UTF88MaxEntropy(Feature):
    name = "utf-8_per8bytes_max_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 8
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = binascii.hexlify(data).decode('ascii')
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        utf8_per8bytes_max_entropy = utils.renyi_entropy(b''.join(chunks), alpha=0) 
        return utf8_per8bytes_max_entropy
    
class UTF816MaxEntropy(Feature):
    name = "utf-8_per16bytes_max_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 16
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = binascii.hexlify(data).decode('ascii')
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        utf8_per16bytes_max_entropy = utils.renyi_entropy(b''.join(chunks), alpha=0) 
        return utf8_per16bytes_max_entropy
    
class UTF832MaxEntropy(Feature):
    name = "utf-8_per32bytes_max_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 32
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = binascii.hexlify(data).decode('ascii')
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        utf8_per32bytes_max_entropy = utils.renyi_entropy(b''.join(chunks), alpha=0) 
        return utf8_per32bytes_max_entropy
    
class UTF864MaxEntropy(Feature):
    name = "utf-8_per64bytes_max_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 64
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = binascii.hexlify(data).decode('ascii')
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        utf8_per64bytes_max_entropy = utils.renyi_entropy(b''.join(chunks), alpha=0) 
        return utf8_per64bytes_max_entropy
    
class HEX4MaxEntropy(Feature):
    name = "hex_per4bytes_max_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 4
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = str(data)
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        hex_per4bytes_max_entropy = utils.renyi_entropy(b''.join(chunks), alpha=0) 
        return hex_per4bytes_max_entropy
    
class HEX8MaxEntropy(Feature):
    name = "hex_per8bytes_max_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 8
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = str(data)
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        hex_per8bytes_max_entropy = utils.renyi_entropy(b''.join(chunks), alpha=0) 
        return hex_per8bytes_max_entropy
    
class HEX16MaxEntropy(Feature):
    name = "hex_per16bytes_max_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 16
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = str(data)
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        hex_per16bytes_max_entropy = utils.renyi_entropy(b''.join(chunks), alpha=0) 
        return hex_per16bytes_max_entropy
    
class HEX32MaxEntropy(Feature):
    name = "hex_per32bytes_max_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 32
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = str(data)
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        hex_per32bytes_max_entropy = utils.renyi_entropy(b''.join(chunks), alpha=0) 
        return hex_per32bytes_max_entropy
    
class HEX64MaxEntropy(Feature):
    name = "hex_per64bytes_max_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 64
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = str(data)
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        hex_per64bytes_max_entropy = utils.renyi_entropy(b''.join(chunks), alpha=0) 
        return hex_per64bytes_max_entropy
    
class BIN4MaxEntropy(Feature):
    name = "bin_per4bytes_max_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 4
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = ''.join(['{:08b}'.format(x) for x in data]) 
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        bin_per4bytes_max_entropy = utils.renyi_entropy(b''.join(chunks), alpha=0) 
        return bin_per4bytes_max_entropy
    
class BIN8MaxEntropy(Feature):
    name = "bin_per8bytes_max_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 8
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = ''.join(['{:08b}'.format(x) for x in data]) 
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        bin_per8bytes_max_entropy = utils.renyi_entropy(b''.join(chunks), alpha=0) 
        return bin_per8bytes_max_entropy
    
class BIN16MaxEntropy(Feature):
    name = "bin_per16bytes_max_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 16
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = ''.join(['{:08b}'.format(x) for x in data]) 
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        bin_per16bytes_max_entropy = utils.renyi_entropy(b''.join(chunks), alpha=0) 
        return bin_per16bytes_max_entropy
    
class BIN32MaxEntropy(Feature):
    name = "bin_per32bytes_max_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 32
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = ''.join(['{:08b}'.format(x) for x in data]) 
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        bin_per32bytes_max_entropy = utils.renyi_entropy(b''.join(chunks), alpha=0) 
        return bin_per32bytes_max_entropy
    
class BIN64MaxEntropy(Feature):
    name = "bin_per64bytes_max_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 64
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = ''.join(['{:08b}'.format(x) for x in data]) 
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        bin_per64bytes_max_entropy = utils.renyi_entropy(b''.join(chunks), alpha=0) 
        return bin_per64bytes_max_entropy
    

class BIN4CollisionEntropy(Feature):
    name = "bin_per4bytes_collision_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 4
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = ''.join(['{:08b}'.format(x) for x in data]) 
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        bin_per4bytes_collision_entropy = utils.renyi_entropy(b''.join(chunks), alpha=2) 
        return bin_per4bytes_collision_entropy
    
class BIN8CollisionEntropy(Feature):
    name = "bin_per8bytes_collision_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 8
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = ''.join(['{:08b}'.format(x) for x in data]) 
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        bin_per8bytes_collision_entropy = utils.renyi_entropy(b''.join(chunks), alpha=2) 
        return bin_per8bytes_collision_entropy
    
class BIN16CollisionEntropy(Feature):
    name = "bin_per16bytes_collision_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 16
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = ''.join(['{:08b}'.format(x) for x in data]) 
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        bin_per16bytes_collision_entropy = utils.renyi_entropy(b''.join(chunks), alpha=2) 
        return bin_per16bytes_collision_entropy
    
class BIN32CollisionEntropy(Feature):
    name = "bin_per32bytes_collision_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 32
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = ''.join(['{:08b}'.format(x) for x in data]) 
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        bin_per32bytes_collision_entropy = utils.renyi_entropy(b''.join(chunks), alpha=2) 
        return bin_per32bytes_collision_entropy
    
class BIN64CollisionEntropy(Feature):
    name = "bin_per64bytes_collision_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 64
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = ''.join(['{:08b}'.format(x) for x in data]) 
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        bin_per64bytes_collision_entropy = utils.renyi_entropy(b''.join(chunks), alpha=2) 
        return bin_per64bytes_collision_entropy
    

class HEX4CollisionEntropy(Feature):
    name = "hex_per4bytes_collision_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 4
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = str(data)
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        hex_per4bytes_collision_entropy = utils.renyi_entropy(b''.join(chunks), alpha=2) 
        return hex_per4bytes_collision_entropy
    
class HEX8CollisionEntropy(Feature):
    name = "hex_per8bytes_collision_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 8
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = str(data) 
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        hex_per8bytes_collision_entropy = utils.renyi_entropy(b''.join(chunks), alpha=2) 
        return hex_per8bytes_collision_entropy
    
class HEX16CollisionEntropy(Feature):
    name = "hex_per16bytes_collision_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 16
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = str(data)
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        hex_per16bytes_collision_entropy = utils.renyi_entropy(b''.join(chunks), alpha=2) 
        return hex_per16bytes_collision_entropy
    
class HEX32CollisionEntropy(Feature):
    name = "hex_per32bytes_collision_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 32
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = str(data)
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        hex_per32bytes_collision_entropy = utils.renyi_entropy(b''.join(chunks), alpha=2) 
        return hex_per32bytes_collision_entropy
    
class HEX64CollisionEntropy(Feature):
    name = "hex_per64bytes_collision_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 64
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = str(data)
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        hex_per64bytes_collision_entropy = utils.renyi_entropy(b''.join(chunks), alpha=2) 
        return hex_per64bytes_collision_entropy
    
class UTF84CollisionEntropy(Feature):
    name = "utf8_per4bytes_collision_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 4
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = binascii.hexlify(data).decode('ascii') 
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        utf8_per4bytes_collision_entropy = utils.renyi_entropy(b''.join(chunks), alpha=2) 
        return utf8_per4bytes_collision_entropy
    
class UTF88CollisionEntropy(Feature):
    name = "utf8_per8bytes_collision_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 8
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = binascii.hexlify(data).decode('ascii')  
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        utf8_per8bytes_collision_entropy = utils.renyi_entropy(b''.join(chunks), alpha=2) 
        return utf8_per8bytes_collision_entropy
    
class UTF816CollisionEntropy(Feature):
    name = "utf8_per16bytes_collision_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 16
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = binascii.hexlify(data).decode('ascii') 
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        utf8_per16bytes_collision_entropy = utils.renyi_entropy(b''.join(chunks), alpha=2) 
        return utf8_per16bytes_collision_entropy
    
class UTF832CollisionEntropy(Feature):
    name = "utf8_per32bytes_collision_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 32
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = binascii.hexlify(data).decode('ascii') 
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        utf8_per32bytes_collision_entropy = utils.renyi_entropy(b''.join(chunks), alpha=2) 
        return utf8_per32bytes_collision_entropy
    
class UTF864CollisionEntropy(Feature):
    name = "utf8_per64bytes_collision_entropy"
    def extract(self, flow: Flow) -> int:
        data = b""
        sequence_length = 64
        for packet in flow.get_packets():
            data += packet.get_payload_data()
        encoded_data = binascii.hexlify(data).decode('ascii') 
        chunks = [bytes(chunk, 'ascii') for chunk in [encoded_data[i:i + sequence_length] for i in range(len(encoded_data) - sequence_length + 1)]] 
        utf8_per64bytes_collision_entropy = utils.renyi_entropy(b''.join(chunks), alpha=2) 
        return utf8_per64bytes_collision_entropy