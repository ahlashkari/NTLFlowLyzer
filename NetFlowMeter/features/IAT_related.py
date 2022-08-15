import numpy as np

from .feature import Feature



# def IAT(packets):
class IAT(Feature):
    def extract(self, packets: object) -> dict:
        times = [packet.get_timestamp() for packet in packets]
        if len(times) > 1:
            for i in range(len(times) - 1):
                times[i] = times[i + 1] - times[i]
            times.pop()
        return times



# def flow_packets_IAT_mean(packets):
class flow_packets_IAT_mean(Feature):
    name = "Packet IAT mean"
    def extract(self, packets: object) -> dict:
        times = IAT(packets)
        if times:
            return np.mean(times)
        else:
            return 0


# def flow_packets_IAT_std(packets):  # should be developed for NaN value
class flow_packets_IAT_std(Feature):
    name = "Packet IAT Std"
    def extract(self, packets: object) -> dict:
        times = IAT(packets)
        try:
            return np.std(times)
        except RuntimeWarning:
            return 0
        except ZeroDivisionError:
            return 0
        except ValueError:
            return 0


# def flow_packets_IAT_max(packets):
class flow_packets_IAT_max(Feature):
    name = "Packet IAT max"
    def extract(self, packets: object) -> dict:
        times = IAT(packets)
        if times:
            return max(times)
        else:
            return 0

# def flow_packets_IAT_min(packets):
class flow_packets_IAT_min(Feature):
    name = "Packet IAT min"
    def extract(self, packets: object) -> dict:
        times = IAT(packets)
        if times:
            return min(times)
        else:
            return 0

# def flow_packets_IAT_sum(packets):
class flow_packets_IAT_sum(Feature):
    name = "Packet IAT Total"
    def extract(self, packets: object) -> dict:
        times = IAT(packets)
        if times:
            return sum(times)
        else:
            return 0
