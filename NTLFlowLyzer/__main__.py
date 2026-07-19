#!/usr/bin/env python3

import argparse

from NTLFlowLyzer.config_loader import ConfigLoader
from .network_flow_analyzer import NTLFlowLyzer
from .batch_runner import run_batch

def args_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='NTLFlowLyzer')
    parser.add_argument('-c', '--config-file', action='store', help='Json config file address.')
    parser.add_argument('-o', '--online-capturing', action='store_true',
                        help='Capturing mode. The default mode is offline capturing.')
    parser.add_argument('-b', '--batch-mode', action='store_true',
                        help='Analyze all the files in the given directory. The default is False.')
    parser.add_argument('-cb', '--continues-batch-mode', action='store_true',
                        help='Continues batch mode. Analyze files in the given directory continuously.'
                            ' Default is False.')
    return parser


def main():
    print("You initiated NTLFlowLyzer!")
    parsed_arguments = args_parser().parse_args()
    config_file_address = "./NTLFlowLyzer/config.json" if parsed_arguments.config_file is None else parsed_arguments.config_file
    online_capturing = parsed_arguments.online_capturing
    if not parsed_arguments.batch_mode:
        config = ConfigLoader(config_file_address)
        network_flow_analyzer = NTLFlowLyzer(config, online_capturing, parsed_arguments.continues_batch_mode)
        network_flow_analyzer.run()
        return

    print(">> Batch mode is on!")
    config = ConfigLoader(config_file_address)
    run_batch(config, online_capturing, parsed_arguments.continues_batch_mode)


if __name__ == "__main__":
    main()
