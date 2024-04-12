#!/usr/bin/env python3

import csv
from .strategy import Strategy


class CSVWriter(Strategy):
    def write(self, file_address: str, data: list, writing_mode: str = 'w',
            only_headers: bool = False) -> None:
        with open(file_address, writing_mode, newline='') as f:
            writer = csv.writer(f)
            if len(data) == 0:
                return

            headers = list(data[0].keys())
            if only_headers:
                writer.writerow(headers)
                return

            for data_row in data:
                row = []
                for header in headers:
                    row.append(data_row[header])
                writer.writerow(row)
