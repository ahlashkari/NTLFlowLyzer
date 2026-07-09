#!/usr/bin/python3

import dpkt
import socket
import multiprocessing
import warnings
from collections import defaultdict, Counter
from multiprocessing import Process, Manager, Pool
from .network_flow_capturer import NetworkFlowCapturer
from .feature_extractor import FeatureExtractor
from .writers import Writer, CSVWriter
from .config_loader import ConfigLoader

from dpkt import ethernet


class NTLFlowLyzer(object):
    def __init__(self, config: ConfigLoader, online_capturing: bool, continues_batch_mode: bool):
        self.__config = config
        self.__continues_batch_mode = continues_batch_mode
        warnings.filterwarnings("ignore")

    def run(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            print(">> Analyzing the", self.__config.pcap_file_address, "...")
            f = open(self.__config.pcap_file_address, 'rb')
            pcap = dpkt.pcap.Reader(f)
            packets_temp = [1 for ts, buf in pcap]
            total_packets = len(packets_temp)
            print(f">> The input PCAP file contains {total_packets} packets.")

            with Manager() as manager:
                self.__flows = manager.list()
                self.__data = manager.list()
                number_of_writer_threads = 1
                number_of_required_threads = 3
                number_of_extractor_threads = self.__config.number_of_threads - number_of_writer_threads
                if self.__config.number_of_threads < number_of_required_threads:
                    print(">> At least 3 threads are required. "
                    "There should be one for the capturer, one for the writer, "
                    "and one or more for the feature extractor."
                    "\nWe set the number of threads based on your CPU cores.")
                    number_of_extractor_threads = multiprocessing.cpu_count() - number_of_writer_threads
                    if multiprocessing.cpu_count() < number_of_required_threads:
                        number_of_extractor_threads = number_of_required_threads - number_of_writer_threads

                self.__capturer_thread_finish = manager.Value('i', False)
                self.__extractor_thread_finish = manager.Value('i', False)
                self.__writed_rows = manager.Value('i', 0)
                self.__output_file_index = manager.Value('i', 1)

                self.__data_lock = manager.Lock()
                self.__flows_lock = manager.Lock()
                self.__feature_extractor_watchdog_lock = manager.Lock()
                self.__writed_rows_lock = manager.Lock()
                self.__output_file_index_lock = manager.Lock()

                capturer = NetworkFlowCapturer(
                        max_flow_duration=self.__config.max_flow_duration,
                        activity_timeout=self.__config.activity_timeout,
                        check_flows_ending_min_flows=self.__config.check_flows_ending_min_flows,
                        capturer_updating_flows_min_value=self.__config.capturer_updating_flows_min_value,
                        read_packets_count_value_log_info=self.__config.read_packets_count_value_log_info,
                        vxlan_ip=self.__config.vxlan_ip,
                        continues_batch_address=self.__config.continues_batch_address,
                        continues_pcap_prefix=self.__config.continues_pcap_prefix,
                        number_of_continues_files=self.__config.number_of_continues_files,
                        continues_batch_mode=self.__continues_batch_mode)
                writer_thread = Process(target=self.writer)
                writer_thread.start()
                with Pool(processes=number_of_extractor_threads) as pool:
                    pool.starmap_async(capturer.capture,
                            [(self.__config.pcap_file_address, self.__flows,
                            self.__flows_lock, self.__capturer_thread_finish,)])
                    self.feature_extractor(pool)
                    pool.close()
                    pool.join()
                    with self.__feature_extractor_watchdog_lock:
                        self.__extractor_thread_finish.set(True)

                writer_thread.join()
            print(">> Results are ready!")

    def feature_extractor(self, pool: Pool):
        feature_extractor = FeatureExtractor(self.__config.floating_point_unit)
        while 1:
            if len(self.__flows) >= self.__config.feature_extractor_min_flows:
                temp_flows = []
                with self.__flows_lock:
                    temp_flows.extend(self.__flows)
                    self.__flows[:] = []
                print(f">> Extracting features of {len(temp_flows)} number of flows...")
                pool.starmap_async(feature_extractor.execute,
                        [(self.__data, self.__data_lock, temp_flows,
                        self.__config.features_ignore_list, self.__config.label)])
                del temp_flows
            if self.__capturer_thread_finish.get():
                if len(self.__flows) == 0:
                    return

                temp_flows = []
                with self.__flows_lock:
                    temp_flows.extend(self.__flows)
                    self.__flows[:] = []
                print(f">> Extracting features of the last {len(temp_flows)} number of flows...")
                pool.starmap_async(feature_extractor.execute,
                        [(self.__data, self.__data_lock, temp_flows,
                        self.__config.features_ignore_list, self.__config.label)])
                del temp_flows


    def writer(self):
        writer = Writer(CSVWriter())
        header_writing_mode = 'w'
        data_writing_mode = 'a+'
        file_address = self.__config.output_file_address
        write_headers = True
        while 1:
            if len(self.__data) >= self.__config.writer_min_rows:
                with self.__writed_rows_lock and self.__output_file_index_lock:
                    if self.__writed_rows.get() > self.__config.max_rows_number:
                        new_file_address = self.__config.output_file_address + str(self.__output_file_index.get())
                        print(f">> {file_address} has reached its maximum number of rows.")
                        print(f">> The {file_address} file will be closed and other rows"
                              f" will be written in the {new_file_address}.")
                        file_address = new_file_address
                        self.__output_file_index.set(self.__output_file_index.get() + 1)
                        write_headers = True
                        self.__writed_rows.set(0)
                if write_headers:
                    writer.write(file_address, self.__data, header_writing_mode, only_headers=True)
                    write_headers = False
                temp_data = []
                with self.__data_lock:
                    temp_data.extend(self.__data)
                    self.__data[:] = []
                    print(f">> Writing {len(temp_data)} flows with extracted features...")
                writer.write(file_address, temp_data, data_writing_mode)
                with self.__writed_rows_lock:
                    self.__writed_rows.set(self.__writed_rows.get() + len(temp_data))
                del temp_data
            with self.__feature_extractor_watchdog_lock:
                if self.__extractor_thread_finish.get():
                    print(">> Extracting finished, lets go for final writing...")
                    temp_data = []
                    with self.__data_lock:
                        temp_data.extend(self.__data)
                        self.__data[:] = []
                    print(f">> Writing the last {len(temp_data)} flows with extracted features...")

                    if write_headers:
                        writer.write(file_address, temp_data, header_writing_mode, only_headers=True)
                        write_headers = False

                    if len(temp_data) > 0:
                        writer.write(file_address, temp_data, data_writing_mode)
                    if len(self.__data) == 0:
                        print(">> Writing finished, lets wrapp up!")
                        return 0
