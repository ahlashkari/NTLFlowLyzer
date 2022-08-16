#!/usr/bin/env python3

import csv
from .strategy import Strategy

class CSVWriter(Strategy):
    #TODO: Improve it
    def write(self, file_address: str, data: list) -> str:
        with open(file_address, 'w') as f:
            writer = csv.writer(f)
            if len(data) == 0:
                print("There is nothing to be shown.")
                return 0
            headers = list(data[0].keys())
            writer.writerow(headers)
            for data_row in data:
                row = []
                for header in headers:
                    row.append(data_row[header])
                writer.writerow(row)
