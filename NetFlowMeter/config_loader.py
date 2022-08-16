#!/usr/bin/env python3

import json

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

        self.read_config_file()

    def read_config_file(self):
        try:
            with open(self.config_file_address) as config_file:
                for key, value in json.loads(config_file.read()).items():
                    setattr(self, key, value)
        except Exception as error:
            print(f">> Error was detected while reading {self.config_file_address}: {str(error)}. "\
                    "Default values will be applied.")
