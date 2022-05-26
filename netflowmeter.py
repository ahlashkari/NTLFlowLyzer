from Reader import flow_capturer
from Writer import csv_writer


class Netflowmeter:
    def __init__(self):
        print('initializing...')
    
    def run(self, input_file):
        capturer = flow_capturer()
        flows =capturer.capture(input_file)
        csvw = csv_writer()
        csvw. create_csv(flows)
