#!/usr/bin/env python3

import json
import multiprocessing

class ConfigLoader:
    def __init__(self, config_file_address: str):
        self.config_file_address = config_file_address
        self.pcap_file_address: str = "./test.pcap"
        self.output_file_address: str = "./"
        self.interface_name: str = "eth0"
        self.max_flow_duration: int = 120000
        self.activity_timeout: int = 5000
        self.protocols: list = []
        self.floating_point_unit: str = ".64f"
        self.features_ignore_list: list = []
        self.number_of_threads: int = multiprocessing.cpu_count()
        self.label = "Unknown"
        self.feature_extractor_min_flows = 4000
        self.writer_min_rows = 6000
        self.read_packets_count_value_log_info = 10000
        self.check_flows_ending_min_flows = 2000
        self.capturer_updating_flows_min_value = 2000
        self.max_rows_number = 900000
        self.read_config_file()

    def read_config_file(self):
        try:
            with open(self.config_file_address) as config_file:
                for key, value in json.loads(config_file.read()).items():
                    setattr(self, key, value)
        except Exception as error:
            print(f">> Error was detected while reading {self.config_file_address}: {str(error)}. "\
                    "Default values will be applied.")
