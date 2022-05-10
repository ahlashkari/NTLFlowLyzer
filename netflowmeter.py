from Reader.reader import flow_capturer
from Reader.packet import Packet
from Reader.flow import Flow
from Writer.csw import csv_writer

class Netflowmeter:
    def __init__(self):
        print('initializing...')
    
    def run(self, input_file):
        capturer = flow_capturer()
        flows = capture (input_file)
        csvw = csv_writer()
        csvw. create_csv(flows)
