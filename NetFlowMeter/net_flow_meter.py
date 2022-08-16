#!/usr/bin/python3

from .net_flow_capturer import NetFlowCapturer
from .feature_extractor import FeatureExtractor
from .writers import Writer, CSVWriter
from .config_loader import ConfigLoader

class NetFlowMeter(object):
    def __init__(self, config_file_address: str, online_capturing: bool):
        print("You initiated Application Flow Meter!")
        self.config_file_address = config_file_address

    def run(self):
        config = ConfigLoader(self.config_file_address)
        net_flow_capturer = NetFlowCapturer(config.max_flow_duration, config.activity_timeout)
        print("> capturing started...")
        flows = net_flow_capturer.capture(config.pcap_file_address)
        print("> capturing ended...")
        print("> features extracting started...")
        feature_extractor = FeatureExtractor(flows, config.floating_point_unit)
        data = feature_extractor.execute(config.features_ignore_list)
        print("> features extracting ended...")
        print("> writing results to", config.output_file_address)
        writer = Writer(CSVWriter())
        writer.write(config.output_file_address, data)
        print("results are ready!")

