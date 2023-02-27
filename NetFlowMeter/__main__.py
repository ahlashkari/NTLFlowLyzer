#!/usr/bin/env python3

import argparse
from .net_flow_meter import NetFlowMeter

def args_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='NetFlowMeter')
    parser.add_argument('-c', '--config-file', action='store', help='Json config file address.')
    parser.add_argument('-o', '--online-capturing', action='store_true',
                        help='Capturing mode. The default mode is offline capturing.')
    return parser


def main():
    parsed_arguments = args_parser().parse_args()
    config_file_address = "./NetFlowMeter/config.json" if parsed_arguments.config_file is None else parsed_arguments.config_file
    online_capturing = parsed_arguments.online_capturing
    net_flow_meter = NetFlowMeter(config_file_address, online_capturing)
    net_flow_meter.run()


if __name__ == "__main__":
    main()
