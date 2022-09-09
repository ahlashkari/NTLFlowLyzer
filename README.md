# NetFlowMeter
TODO: update these values:
![](https://img.shields.io/github/stars/pandao/editor.md.svg) ![](https://img.shields.io/github/forks/pandao/editor.md.svg) ![](https://img.shields.io/github/tag/pandao/editor.md.svg) ![](https://img.shields.io/github/release/pandao/editor.md.svg) ![](https://img.shields.io/github/issues/pandao/editor.md.svg)

A Python open-source project to extract features from network traffic flow. 


## Project Team members 

* [**Arash Habibi Lashkari:**](http://ahlashkari.com/index.asp) Founder and supervisor

* [**Moein Shafi:**](https://github.com/moein-shafi) Researcher and developer - York University

* [**Sepideh Niktabe:**](https://github.com/sepideh2020) Researcher and developer - York University

* [**Mehrsa Khoshpasand:**](https://github.com/Khoshpasand-mehrsa) Researcher and developer - York University

* [**Parisa Ghanad:**](https://github.com/parishisit) Researcher and developer - Amirkabir University


### Acknowledgement 

This project has been made possible through funding from the [**Mitacs Global Research Internship**](https://www.mitacs.ca/en/programs/globalink/globalink-research-internship). 



# Table of Contents

- [Installation](#installation)
- [Architecture](#architecture)
- [Extracted Features](#extracted-features)
  * [Definitions](#definitions)
  * [Statistical Information Calculation](#statistical-information-calculation)
- [Output](#output)
- [Development](#development)


# Installation

You must install the requirements in your system before you can begin installing or running anything. To do so, you can easily run this command:

```bash
sudo pip3 install -r requirements.txt
```

You are now ready to install AppFlowMeter. In order to do so, you should run this command, which will install the AppFlowMeter package in your system:

```bash
sudo python3 setup.py install
```

Finally, to execute the program, run this command:

```bash
sudo net-flow-meter
```
Also, you can use `-h` to see different options of the program.

Moreover, this project has been successfully tested on Ubuntu 20.04. It should work on other versions of Ubuntu OS (or even Debian OS) as long as your system has the necessary python3 packages (you can see the required packages in the `requirements.txt` file).

TODO: explain different options of arg parser.

TODO: explain how to use the config file.


# Architecture


![](./Architecture.svg)

                
----

# Extracted Features
                
We have currenlty 80 features that are as follows:

1. Duration
1. Packets Count
1. Forward Packets Count
1. Backward Packets Count
1. Total Payload Bytes
1. Forward Total Payload Bytes
1. Backward Total Payload Bytes
1. Payload Bytes Max
1. Payload Bytes Min
1. Payload Bytes Mean
1. Payload Bytes Std
1. Forward Payload Bytes Max
1. Forward Payload Bytes Min
1. Forward Payload Bytes Mean
1. Forward Payload Bytes Std
1. Backward Payload Bytes Max
1. Backward Payload Bytes Min
1. Backward Payload Bytes Mean
1. Backward Payload Bytes Std
1. Forward Avg Segment Size
1. Backward Avg Segment Size
1. Avg SegmentSize
1. Active Min
1. Active Max
1. Active Mean
1. Active Std
1. Idle Min
1. Idle Max
1. Idle Mean
1. Idle Std
1. Bytes Rate
1. Forward Bytes Rate
1. Backward Bytes Rate
1. Packets Rate
1. Backward Packets Rate
1. Forward Packets Rate
1. Avg Forward Bytes Per Bulk
1. Avg Forward Packets Per Bulk
1. Avg Forward Bulk Rate
1. Avg Backward Bytes Per Bulk
1. Avg Backward Packets Per Bulk
1. Avg Backward Bulk Rate
1. Forward Bulk State Count
1. Forward Bulk Size Total
1. Forward Bulk Packet Count
1. Forward Bulk Duration
1. Backward Bulk State Count
1. Backward Bulk Size Total
1. Backward Bulk Packet Count
1. Backward Bulk Duration
1. FIN Flag Counts
1. PSH Flag Counts
1. URG Flag Counts
1. ECE Flag Counts
1. SYN Flag Counts
1. ACK Flag Counts
1. CWR Flag Counts
1. RST Flag Counts
1. IAT
1. Packets IAT Mean
1. Packets IAT Std
1. Packets IAT Max
1. Packets IAT Min
1. Packets IAT Sum
1. ForwardIAT
1. Forward Packets IATMean
1. Forward Packets IATStd
1. Forward Packets IATMax
1. Forward Packets IATMin
1. Forward Packets IATSum
1. Backward IAT
1. Backward Packets IATMean
1. Backward Packets IATStd
1. Backward Packets IATMax
1. Backward Packets IATMin
1. Backward Packets IATSum
1. Subflow Forward Packets
1. Subflow Backward Packets
1. Subflow Forward Bytes
1. Subflow Backward Bytes


TODO: complete the definitions
## Definitions

+ **IAT**
+ **Bulk**
+ **Subflow**
+ **Idle**

## Statistical Information Calculation

We use differnet libraries to calculate various mathematical equations. Below you can see the libraries and their brief definition based on their documentations:

+ [**statistics**](https://docs.python.org/3/library/statistics.html)

     This module provides functions for calculating mathematical statistics of numeric (Real-valued) data.

     The module is not intended to be a competitor to third-party libraries such as NumPy, SciPy, or proprietary full-featured statistics packages aimed at professional statisticians such as Minitab, SAS and Matlab. It is aimed at the level of graphing and scientific calculators.


Nine mathematical functions are used to extract different features. You can see how those functions are calculated in the AppFlowMeter below:

1. Min

      You know what it means :). The 'min' function (Python built-in) calculates the minimum value in a given list.

1. Max

      Same as min. The 'max' function (Python built-in) calculates the minimum value in a given list.

1. Mean

      The ['mean'](https://docs.python.org/3/library/statistics.html#statistics.mean) function from 'statistics' library (Python built-in) calculates the mean value of a given list. According to the library documentation:
        
      The arithmetic mean is the sum of the data divided by the number of data points. It is commonly called “the average”, although it is only one of many different mathematical averages. It is a measure of the central location of the data.

      TODO: use 'fmean' instead of mean (it is new in python 3.8). According to the library documentation:
        
      This runs faster than the mean() function and it always returns a float. The data may be a sequence or iterable. If the input dataset is empty, raises a StatisticsError.


1. Standard Deviation

      The ['pstdev'](https://docs.python.org/3/library/statistics.html#statistics.pstdev) function from 'statistics' library (Python built-in) calculates the mean value of a given list. According to the library documentation:

      Return the population standard deviation (the square root of the population variance). See pvariance() for arguments and other details.




----
     
     
TODO: put more examples here

# Output


| flow_id | timestamp | src_ip |  src_port  |  dst_ip  |  dst_port  |  protocol  |  duration  |  packets_count  |  fwd_packets_count  |  bwd_packets_count  |  total_payload_bytes  |  fwd_total_payload_bytes  |  bwd_total_payload_bytes  |  payload_bytes_max  |  payload_bytes_min  |  payload_bytes_mean  |  payload_bytes_std  |  fwd_payload_bytes_max  |  fwd_payload_bytes_min  |  fwd_payload_bytes_mean  |  fwd_payload_bytes_std  |  bwd_payload_bytes_max  |  bwd_payload_bytes_min  |  bwd_payload_bytes_mean  |  bwd_payload_bytes_std  |  fwd_avg_segment_size  |  bwd_avg_segment_size  |  avg_segment_size  |  active_min  |  active_max  |  active_mean  |  active_std  |  idle_min  |  idle_max  |  idle_mean  |  idle_std  |  bytes_rate  |  fwd_bytes_rate  |  bwd_bytes_rate  |  packets_rate  |  bwd_packets_rate  |  fwd_packets_rate  |  avg_fwd_bytes_per_bulk  |  avg_fwd_packets_per_bulk  |  avg_fwd_bulk_rate  |  avg_bwd_bytes_per_bulk  |  avg_bwd_packets_bulk_rate  |  avg_bwd_bulk_rate  |  fwd_bulk_state_count  |  fwd_bulk_total_size  |  fwd_bulk_per_packet  |  fwd_bulk_duration  |  bwd_bulk_state_count  |  bwd_bulk_total_size  |  bwd_bulk_per_packet  |  bwd_bulk_duration  |  fin_flag_counts  |  psh_flag_counts  |  urg_flag_counts  |  ece_flag_counts  |  syn_flag_counts  |  ack_flag_counts  |  cwr_flag_counts  |  rst_flag_counts  |  IAT  |  packets_IAT_mean  |  packet_IAT_std  |  packet_IAT_max  |  packet_IAT_min  |  packet_IAT_total  |  fwd_IAT  |  fwd_packets_IAT_mean  |  fwd_packets_IAT_std  |  fwd_packets_IAT_max  |  fwd_packets_IAT_min  |  fwd_packets_IAT_total  |  bwd_IAT  |  bwd_packets_IAT_mean  |  bwd_packets_IAT_std  |  bwd_packets_IAT_max  |  bwd_packets_IAT_min  |  bwd_packets_IAT_total  |  subflow_fwd_packets  |  subflow_bwd_packets  |  subflow_fwd_bytes  |  subflow_bwd_bytes  |
| :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :----------------: |  :----------------: |
|  192.168.43.116_52790_104.21.69.158_443_TCP_2022-07-27 18:14:08.578480  |  2022-07-27 14:14:08.578480  |  192.168.43.116  |  52790  |  104.21.69.158  |  443  |  TCP  |  0.343462  |  14  |  6  |  8  |  4846  |  305  |  4541  |  1454  |  54  |  401.8571428571428327813919167965650558471679687500000000000000000000  |  560.3270546415417356911348178982734680175781250000000000000000000000  |  1454  |  54  |  401.8571428571428327813919167965650558471679687500000000000000000000  |  560.3270546415417356911348178982734680175781250000000000000000000000  |  1454  |  54  |  401.8571428571428327813919167965650558471679687500000000000000000000  |  560.3270546415417356911348178982734680175781250000000000000000000000  |  50.833333333333336  |  567.625  |  346.14285714285717  |  0  |  0  |  0  |  0  |  0  |  0  |  0  |  0  |  14109.27555304517  |  888.0167238297105  |  13221.25882921546  |  40.76142338890474  |  23.292241936516994  |  17.469181452387748  |  0  |  0  |  0  |  4541.0  |  4.0  |  1795571.3720838276  |  0  |  0  |  0  |  0  |  1  |  4541  |  4  |  0.002529  |  2  |  3  |  0  |  0  |  2  |  13  |  0  |  0  |  "[0.105479, 9.1e-05, 0.017816, 0.029934, 0.088577, 0.000417, 0.000107, 0.001526, 0.000479, 0.00016, 0.003068, 0.057828, 0.03798]"  |  0.0264201538461538466828759652571534388698637485504150390625000000  |  0.0349830592470702014806782642608595779165625572204589843750000000  |  0.105479  |  9.1e-05  |  0.343462  |  "[0.10557, 0.017816, 0.119035, 0.002165, 0.003068]"  |  0.0495307999999999998275157508942356798797845840454101562500000000  |  0.0517288412528252999900146846812276635318994522094726562500000000  |  0.119035  |  0.002165  |  0.24765399999999999  |  "[0.047841, 0.088577, 0.000417, 0.001633, 0.000479, 0.061056, 0.03798]"  |  0.0339975714285714256113202225151326274499297142028808593750000000  |  0.0321096063145201032762443560386600438505411148071289062500000000  |  0.088577  |  0.000417  |  0.237983  |  0  |  0  |  0  |  0  |


----

TODO: complete this part
# Development

Talk about how other people can improve the NetFlowMeter and adding new features.

