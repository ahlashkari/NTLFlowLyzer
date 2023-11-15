#!/usr/bin/env python3

from .strategy import Strategy
from .csv_writer import CSVWriter

class Writer(object):
    strategy: Strategy

    def __init__(self, strategy: Strategy = None) -> None:
        if strategy is not None:
            self.strategy = strategy
        else:
            self.strategy = CSVWriter()

    def write(self, file_address: str, data: list, writing_mode: str = 'w',
            only_headers: bool = False) -> None:
        self.strategy.write(file_address, data, writing_mode, only_headers)