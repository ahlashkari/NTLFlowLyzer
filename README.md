# NLFlowLyzer
## Network Layer Flow Analyzer

As part of the Understanding Cybersecurity Series (UCS), NLFlowLyzer is a Python open-source project to extract network layer features from a TCP-based network traffic for Anomaly Profiling (AP) which is the second component of the [**NetFlowLyzer**](https://github.com/ahlashkari/NetFlowLyzer).  

NLFlowLyzer is generating bidirectional flows from a TCP-based network traffic, where the first packet determines the forward (source to destination) and backward (destination to source) directions, hence the statistical time-related features can be calculated separately in the forward and backward directions. Additional functionalities include, selecting features from the list of existing features, adding new features, and controlling the duration of flow timeout.

NOTE: TCP flows are usually terminated upon connection teardown (by FIN or RST packet) while UDP flows are terminated by a flow timeout. The flow timeout value can be assigned arbitrarily by the individual scheme e.g., 600 seconds for both TCP and UDP.


# Table of Contents

- [Installation](#installation)
- [Architecture](#architecture)
- [Extracted Features](#extracted-features)
  * [Statistical Information Calculation](#statistical-information-calculation)
- [Output](#output)
- [Copyright (c) 2023](#copyright-c-2023)
- [Contributing](#contributing)
- [Project Team Members](#project-team-members)
- [Acknowledgment](#acknowledgment)

# Installation

You must install the requirements in your system before you can begin installing or running anything. The following two subsections illustrate how you can run NLFlowLyzer in your system whether it is Linux or Windows based. 

* Linux: 

   You must install the requirements in your system before you can begin installing or running anything. To do so, you can easily run this command:

   ```bash
   sudo pip3 install -r requirements.txt
   ```

   You are now ready to install IoTNetLyzer. In order to do so, you should run this command, which will install the IoTNetLyzer package in your system:

   ```bash
   sudo python3 setup.py install
   ```

   Finally, to execute the program, you have to prepare a config file in Json format (example is available in NlFlowLyzer/config.json) and then run this command:

   ```bash
   sudo nlflowlyzer -c config.json
   ```
   It is mandatory to have the 'input_pcap_file' in your config file. Other things are optional.

   Also, you can use `-h` to see different options of the program.

* Windows: 

  For installing the project in windows can easily run this command in windows commenad lind (CMD):

  ```bash
  pip install -r requirements.txt
  ```

  In order to nstall the IoTNetLyzer package in your system run the below command in CMD:

  ```bash
  pip install .
  ```

  Finally, to execute the program, you have to prepare a config file in Json format (example is available in NlFlowLyzer/config.json) and then 

  ```bash
  nlflowlyzer -c config.json
  ```
  It is mandatory to have the 'input_pcap_file' in your config file. Other things are optional.
  
  Also, you can use `-h` to see different options of the program.



Moreover, this project has been successfully tested on Ubuntu 20.04. It should work on other versions of Ubuntu OS (or even Debian OS) as long as your system has the necessary python3 packages (you can see the required packages in the `requirements.txt` file).



# Architecture


![](./Architecture.svg)

                
----

# Extracted Features
                
We have currenlty 114 features that are as follows:

1. Duration
1. PacketsCount
1. FwdPacketsCount
1. BwdPacketsCount
1. TotalPayloadBytes
1. FwdTotalPayloadBytes
1. BwdTotalPayloadBytes
1. PayloadBytesMax
1. PayloadBytesMin
1. PayloadBytesMean
1. PayloadBytesStd
1. PayloadBytesVariance
1. FwdPayloadBytesMax
1. FwdPayloadBytesMin
1. FwdPayloadBytesMean
1. FwdPayloadBytesStd
1. FwdPayloadBytesVariance
1. BwdPayloadBytesMax
1. BwdPayloadBytesMin
1. BwdPayloadBytesMean
1. BwdPayloadBytesStd
1. BwdPayloadBytesVariance
1. TotalHeaderBytes
1. MaxHeaderBytes
1. MinHeaderBytes
1. MeanHeaderBytes
1. StdHeaderBytes
1. FwdTotalHeaderBytes
1. FwdMaxHeaderBytes
1. FwdMinHeaderBytes
1. FwdMeanHeaderBytes
1. FwdStdHeaderBytes
1. BwdTotalHeaderBytes
1. BwdMaxHeaderBytes
1. BwdMinHeaderBytes
1. BwdMeanHeaderBytes
1. BwdStdHeaderBytes
1. FwdAvgSegmentSize
1. BwdAvgSegmentSize
1. AvgSegmentSize
1. FwdInitWinBytes
1. BwdInitWinBytes
1. ActiveMin
1. ActiveMax
1. ActiveMean
1. ActiveStd
1. IdleMin
1. IdleMax
1. IdleMean
1. IdleStd
1. BytesRate
1. FwdBytesRate
1. BwdBytesRate
1. PacketsRate
1. BwdPacketsRate
1. FwdPacketsRate
1. DownUpRate
1. AvgFwdBytesPerBulk
1. AvgFwdPacketsPerBulk
1. AvgFwdBulkRate
1. AvgBwdBytesPerBulk
1. AvgBwdPacketsPerBulk
1. AvgBwdBulkRate
1. FwdBulkStateCount
1. FwdBulkSizeTotal
1. FwdBulkPacketCount
1. FwdBulkDuration
1. BwdBulkStateCount
1. BwdBulkSizeTotal
1. BwdBulkPacketCount
1. BwdBulkDuration
1. FINFlagCounts
1. PSHFlagCounts
1. URGFlagCounts
1. ECEFlagCounts
1. SYNFlagCounts
1. ACKFlagCounts
1. CWRFlagCounts
1. RSTFlagCounts
1. FwdFINFlagCounts
1. FwdPSHFlagCounts
1. FwdURGFlagCounts
1. FwdECEFlagCounts
1. FwdSYNFlagCounts
1. FwdACKFlagCounts
1. FwdCWRFlagCounts
1. FwdRSTFlagCounts
1. BwdFINFlagCounts
1. BwdPSHFlagCounts
1. BwdURGFlagCounts
1. BwdECEFlagCounts
1. BwdSYNFlagCounts
1. BwdACKFlagCounts
1. BwdCWRFlagCounts
1. BwdRSTFlagCounts
1. PacketsIATMean
1. PacketsIATStd
1. PacketsIATMax
1. PacketsIATMin
1. PacketsIATSum
1. FwdPacketsIATMean
1. FwdPacketsIATStd
1. FwdPacketsIATMax
1. FwdPacketsIATMin
1. FwdPacketsIATSum
1. BwdPacketsIATMean
1. BwdPacketsIATStd
1. BwdPacketsIATMax
1. BwdPacketsIATMin
1. BwdPacketsIATSum
1. SubflowFwdPackets
1. SubflowBwdPackets
1. SubflowFwdBytes
1. SubflowBwdBytes



## Statistical Information Calculation

We use differnet libraries to calculate various mathematical equations. Below you can see the libraries and their brief definition based on their documentations:

+ [**statistics**](https://docs.python.org/3/library/statistics.html)

     This module provides functions for calculating mathematical statistics of numeric (Real-valued) data.

     The module is not intended to be a competitor to third-party libraries such as NumPy, SciPy, or proprietary full-featured statistics packages aimed at professional statisticians such as Minitab, SAS and Matlab. It is aimed at the level of graphing and scientific calculators.


Nine mathematical functions are used to extract different features. You can see how those functions are calculated in the NLFlowLyzer below:

1. Min

      You know what it means :). The 'min' function (Python built-in) calculates the minimum value in a given list.

1. Max

      Same as min. The 'max' function (Python built-in) calculates the minimum value in a given list.

1. Mean

      The ['mean'](https://docs.python.org/3/library/statistics.html#statistics.mean) function from 'statistics' library (Python built-in) calculates the mean value of a given list. According to the library documentation:
        
      The arithmetic mean is the sum of the data divided by the number of data points. It is commonly called “the average”, although it is only one of many different mathematical averages. It is a measure of the central location of the data.

        
      This runs faster than the mean() function and it always returns a float. The data may be a sequence or iterable. If the input dataset is empty, raises a StatisticsError.


1. Standard Deviation

      The ['pstdev'](https://docs.python.org/3/library/statistics.html#statistics.pstdev) function from 'statistics' library (Python built-in) calculates the mean value of a given list. According to the library documentation:

      Return the population standard deviation (the square root of the population variance). See pvariance() for arguments and other details.




----
     
     

# Output


| flow_id | timestamp | src_ip | src_port | dst_ip | dst_port | protocol | duration | packets_count | fwd_packets_count | bwd_packets_count | total_payload_bytes | fwd_total_payload_bytes | bwd_total_payload_bytes | payload_bytes_max | payload_bytes_min | payload_bytes_mean | payload_bytes_std | payload_bytes_variance | fwd_payload_bytes_max | fwd_payload_bytes_min | fwd_payload_bytes_mean | fwd_payload_bytes_std | fwd_payload_bytes_variance | bwd_payload_bytes_max | bwd_payload_bytes_min | bwd_payload_bytes_mean | bwd_payload_bytes_std | bwd_payload_bytes_variance | total_header_bytes | max_header_bytes | min_header_bytes | mean_header_bytes | std_header_bytes | fwd_total_header_bytes | fwd_max_header_bytes | fwd_min_header_bytes | fwd_mean_header_bytes | fwd_std_header_bytes | bwd_total_header_bytes | bwd_max_header_bytes | bwd_min_header_bytes | bwd_mean_header_bytes | bwd_std_header_bytes | fwd_avg_segment_size | bwd_avg_segment_size | avg_segment_size | fwd_init_win_bytes | bwd_init_win_bytes | active_min | active_max | active_mean | active_std | idle_min | idle_max | idle_mean | idle_std | bytes_rate | fwd_bytes_rate | bwd_bytes_rate | packets_rate | bwd_packets_rate | fwd_packets_rate | down_up_rate | avg_fwd_bytes_per_bulk | avg_fwd_packets_per_bulk | avg_fwd_bulk_rate | avg_bwd_bytes_per_bulk | avg_bwd_packets_bulk_rate | avg_bwd_bulk_rate | fwd_bulk_state_count | fwd_bulk_total_size | fwd_bulk_per_packet | fwd_bulk_duration | bwd_bulk_state_count | bwd_bulk_total_size | bwd_bulk_per_packet | bwd_bulk_duration | fin_flag_counts | psh_flag_counts | urg_flag_counts | ece_flag_counts | syn_flag_counts | ack_flag_counts | cwr_flag_counts | rst_flag_counts | fwd_fin_flag_counts | fwd_psh_flag_counts | fwd_urg_flag_counts | fwd_ece_flag_counts | fwd_syn_flag_counts | fwd_ack_flag_counts | fwd_cwr_flag_counts | fwd_rst_flag_counts | bwd_fin_flag_counts | bwd_psh_flag_counts | bwd_urg_flag_counts | bwd_ece_flag_counts | bwd_syn_flag_counts | bwd_ack_flag_counts | bwd_cwr_flag_counts | bwd_rst_flag_counts | packets_IAT_mean | packet_IAT_std | packet_IAT_max | packet_IAT_min | packet_IAT_total | fwd_packets_IAT_mean | fwd_packets_IAT_std | fwd_packets_IAT_max | fwd_packets_IAT_min | fwd_packets_IAT_total | bwd_packets_IAT_mean | bwd_packets_IAT_std | bwd_packets_IAT_max | bwd_packets_IAT_min | bwd_packets_IAT_total | subflow_fwd_packets | subflow_bwd_packets | subflow_fwd_bytes | subflow_bwd_bytes |
| :-----------------------------------------------------------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: |  :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: |  :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: |  :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: |  :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: |  :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: |  :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: |  :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: |  :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: |  :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: |  :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: |  :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: |  :----------------: 
| 192.168.43.116_52807_94.182.113.152_443_TCP_2022-07-27 18:15:06.851907 | 2022-07-27 14:15:06.851907 | 192.168.43.116 | 52807 | 94.182.113.152 | 443 | TCP | 35.190285 | 160 | 57 | 103 | 107851 | 6506 | 101345 | 1400 | 0 | 674.068 | 641.577 | 411621.751 | 1400 | 0 | 674.068 | 641.577 | 28619.489 | 1400 | 0 | 674.068 | 641.577 | 354057.946 | 3224 | 32 | 20 | 20.150 | 1.333 | 1152 | 32 | 20 | 20.210 | 1.575 | 2072 | 32 | 20 | 20.116 | 1.176 | 114.140 | 983.932 | 674.06875 | 64240 | 64240 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 3064.794729568118 | 184.88057144180559 | 2879.914158126312 | 4.5467094114185205 | 2.9269441836006727 | 1.6197652278178478 | 1.8070175438596492 | 1402.0 | 8.0 | 135714.63143119888 | 24633.25 | 20.0 | 1305955.0159710534 | 2 | 2804 | 16 | 0.020661 | 4 | 98533 | 80 | 0.075449 | 2 | 87 | 0 | 0 | 2 | 159 | 0 | 0 | 1 | 31 | 0 | 0 | 1 | 56 | 0 | 0 | 1 | 56 | 0 | 0 | 1 | 103 | 0 | 0 | 0.2213225471698113400176310960887349210679531097412109375000000000 | 2.38779124547500565256541449343785643577575683593750 | 29.947797 | 0.0 | 35.190285 | 0.6283979464285713856241954999859444797039031982421875000000000000 | 3.99159454798977897382883384125307202339172363281250 | 29.947841 | 5.7e-05 | 35.190285 | 0.3447076274509803806012087079579941928386688232421875000000000000 | 2.978997962197461379929563918267376720905303955078125 | 29.991346 | 0.0 | 35.160177999999995 | 28.5 | 51.5 | 3253.0 | 3253.0 |
| 192.168.43.116_64362_104.21.69.158_443_UDP_2022-07-27 18:14:09.705289 | 2022-07-27 14:14:09.705289 | 192.168.43.116 | 64362 | 104.21.69.158 | 443 | UDP | 12.018215 | 1834 | 375 | 1459 | 1665985 | 37224 | 1628761 | 1250 | 23 | 908.388 | 474.288 | 224949.652 | 1250 | 23 | 908.388 | 474.288 | 23478.770 | 1250 | 23 | 908.388 | 474.288 | 65212.988 | 14672 | 8 | 8 | 8 | 0 | 3000 | 8 | 8 | 8 | 0 | 11672 | 8 | 8 | 8 | 0 | 99.264 | 1116.354 | 908.388 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 138621.66719433793 | 3097.2985588958095 | 135524.3686354421 | 152.60169667458936 | 121.39905967733145 | 31.202636997257912 | 3.8906666666666667 | 1750.5 | 7.916666666666667 | 483352.1249913712 | 10010.292517006803 | 8.82312925170068 | 2534980.3525684644 | 12 | 21006 | 95 | 0.043459 | 147 | 1471513 | 1297 | 0.580483 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0.0065565821058374247967681647253357368754222989082336425781250000 | 0.1664041060697670770807121698453556746244430541992187500000000000 | 6.901232 | 0.0 | 12.018215000000003 | 0.0321342647058823552286277447365137049928307533264160156250000000 | 0.3685040949375026908541030934429727494716644287109375000000000000 | 6.901232 | 8.5e-05 | 12.018215000000003 | 0.0081416961591220856492290280925772094633430242538452148437500000 | 0.1911619764558343259608363950974307954311370849609375000000000000 | 7.041971 | 0.0 | 11.870592999999998 | 187.5 | 729.5 | 18612.0 | 18612.0 |
| 192.168.43.116_52790_104.21.69.158_443_TCP_2022-07-27 18:14:08.578480 | 2022-07-27 14:14:08.578480 | 192.168.43.116 | 52790 | 104.21.69.158 | 443 | TCP | 0.343462 | 14 | 6 | 8 | 4846 | 305 | 4541 | 1400 | 0 | 346.142 | 561.369 | 315135.551 | 1400 | 0 | 346.142 | 561.369 | 12920.138 | 1400 | 0 | 346.142 | 561.369 | 427336.984 | 304 | 32 | 20 | 21.714 | 4.199 | 132 | 32 | 20 | 22 | 4.472 | 172 | 32 | 20 | 21.5000 | 3.968 | 50.833 | 567.625 | 346.142 | 64240 | 65535 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 14109.27555304517 | 888.0167238297105 | 13221.25882921546 | 40.76142338890474 | 23.292241936516994 | 17.469181452387748 | 1.3333333333333333 | 0 | 0 | 0 | 4541.0 | 4.0 | 1795571.3720838276 | 0 | 0 | 0 | 0 | 1 | 4541 | 4 | 0.002529 | 2 | 3 | 0 | 0 | 2 | 13 | 0 | 0 | 1 | 1 | 0 | 0 | 1 | 5 | 0 | 0 | 1 | 2 | 0 | 0 | 1 | 8 | 0 | 0 | 0.0264201538461538466828759652571534388698637485504150390625000000 | 0.0349830592470702014806782642608595779165625572204589843750000000 | 0.105479 | 9.1e-05 | 0.343462 | 0.0495307999999999998275157508942356798797845840454101562500000000 | 0.0517288412528252999900146846812276635318994522094726562500000000 | 0.119035 | 0.002165 | 0.24765399999999999 | 0.0339975714285714256113202225151326274499297142028808593750000000 | 0.0321096063145201032762443560386600438505411148071289062500000000 | 0.088577 | 0.000417 | 0.237983 | 0 | 0 | 0 | 0 |
| 192.168.43.116_52765_142.250.186.133_443_TCP_2022-07-27 18:14:04.374890 | 2022-07-27 14:14:04.374890 | 192.168.43.116 | 52765 | 142.250.186.133 | 443 | TCP | 100.345666 | 276 | 91 | 185 | 204871 | 38998 | 165873 | 1400 | 0 | 742.286 | 656.560 | 431071.066 | 1400 | 0 | 742.286 | 656.560 | 363470.203 | 1400 | 0 | 742.286 | 656.560 | 392090.010 | 5592 | 32 | 20 | 20.260 | 1.749 | 1820 | 20 | 20 | 20 | 0 | 3772 | 32 | 20 | 20.389 | 2.125 | 428.549 | 896.6108108108108 | 742.286231884058 | 65527 | 2174 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2041.652700775338 | 388.63661535715954 | 1653.0160854181786 | 2.750492482654906 | 1.8436272075766582 | 0.9068652750782481 | 2.032967032967033 | 7021.666666666667 | 7.0 | 48624.59229439288 | 31408.8 | 25.2 | 258988.2498453927 | 3 | 21065 | 21 | 0.433217 | 5 | 157044 | 126 | 0.606375 | 0 | 114 | 0 | 0 | 0 | 276 | 0 | 0 | 0 | 27 | 0 | 0 | 0 | 91 | 0 | 0 | 0 | 87 | 0 | 0 | 0 | 185 | 0 | 0 | 0.3648933309090909293814775082864798605442047119140625000000000000 | 3.436409533900813162432541503221727907657623291015625 | 45.010319 | 0.0 | 100.345666 | 1.114645355555555550353119542705826461315155029296875 | 5.943249669104329058200164581649005413055419921875 | 45.046832 | 0.0 | 100.31808199999999 | 0.5450481086956522336350872137700207531452178955078125000000000000 | 4.19262459319028391035999447922222316265106201171875 | 45.030952 | 0.0 | 100.28885200000002 | 18.2 | 37.0 | 7799.6 | 7799.6 |
| 192.168.43.116_54924_142.250.185.106_443_UDP_2022-07-27 18:14:08.127456 | 2022-07-27 14:14:08.127456 | 192.168.43.116 | 54924 | 142.250.185.106 | 443 | UDP | 0.291493 | 18 | 9 | 9 | 6376 | 2440 | 3936 | 1250 | 25 | 354.222 | 469.385 | 220322.506 | 1250 | 25 | 354.222 | 469.385 | 184884.320 | 1250 | 25 | 354.222 | 469.385 | 241945.777 | 144 | 8 | 8 | 8 | 0 | 72 | 8 | 8 | 8 | 0 | 72 | 8 | 8 | 8 | 0 | 271.111 | 437.333 | 354.222 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 21873.595592346985 | 8370.698438727517 | 13502.89715361947 | 61.7510540561866 | 30.8755270280933 | 30.8755270280933 | 1.0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0.0171466470588235303518231944508443120867013931274414062500000000 | 0.0263312681938975730322471946465157088823616504669189453125000000 | 0.100056 | 0.000165 | 0.29149300000000006 | 0.028 | 0.036 | 0.101686 | 0.000165 | 0.230766 | 0.022 | 0.023 | 0.065875 | 0.000285 | 0.17733400000000002 | 0 | 0 | 0 | 0 |
| 192.168.43.116_52794_151.101.114.133_443_TCP_2022-07-27 18:14:11.191157 | 2022-07-27 14:14:11.191157 | 192.168.43.116 | 52794 | 151.101.114.133 | 443 | TCP | 91.000385 | 36 | 15 | 21 | 8425 | 2223 | 6202 | 1400 | 0 | 234.027 | 394.962 | 155995.582 | 1400 | 0 | 234.027 | 394.962 | 42528.159 | 1400 | 0 | 234.027 | 394.962 | 228023.650 | 768 | 32 | 20 | 21.333 | 3.771 | 312 | 32 | 20 | 20.800 | 2.993 | 456 | 32 | 20 | 21.714 | 4.199 | 148.2 | 295.333 | 234.027 | 64240 | 65535 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 92.58202588923113 | 24.428468077360332 | 68.1535578118708 | 0.3956027219005722 | 0.23076825444200044 | 0.16483446745857175 | 1.4 | 0 | 0 | 0 | 4796.0 | 4.0 | 4715830.87512291 | 0 | 0 | 0 | 0 | 1 | 4796 | 4 | 0.001017 | 0 | 16 | 0 | 0 | 2 | 35 | 0 | 0 | 0 | 8 | 0 | 0 | 1 | 14 | 0 | 0 | 0 | 8 | 0 | 0 | 1 | 21 | 0 | 0 | 2.600 | 10.439 | 45.008387 | 0.0 | 91.000385 | 6.498 | 15.747 | 45.138092 | 0.000215 | 90.98239699999999 | 4.545 | 13.512 | 45.135349 | 0.0 | 90.900005 | 7.5 | 10.5 | 1111.5 | 1111.5 |
| 192.168.43.116_52834_80.66.179.18_443_TCP_2022-07-27 18:15:26.541156 | 2022-07-27 14:15:26.541156 | 192.168.43.116 | 52834 | 80.66.179.18 | 443 | TCP | 2.823269 | 2754 | 497 | 2257 | 3134937 | 3564 | 3131373 | 1400 | 0 | 1138.321 | 542.669 | 294490.488 | 1400 | 0 | 1138.321 | 542.669 | 1736.302 | 1400 | 0 | 1138.321 | 542.669 | 15162.421 | 55832 | 40 | 20 | 20.273 | 2.075 | 10680 | 40 | 20 | 21.488 | 4.665 | 45152 | 32 | 20 | 20.005 | 0.252 | 7.17102615694165 | 1387.4049623393885 | 1138.3213507625273 | 64240 | 29200 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1110392.5980839941 | 1262.3664270035906 | 1109130.2316569907 | 975.4649663209564 | 799.4278972354389 | 176.03706908551754 | 4.541247484909457 | 582.0 | 4.0 | 32786.88524590164 | 195188.4375 | 140.0625 | 2555729.8648243896 | 1 | 582 | 4 | 0.017751 | 16 | 3123015 | 2241 | 1.221966 | 0 | 413 | 0 | 0 | 2 | 2753 | 0 | 0 | 0 | 26 | 0 | 0 | 1 | 496 | 0 | 0 | 0 | 387 | 0 | 0 | 1 | 2257 | 0 | 0 | 0.0010255245187068653175271881750063585059251636266708374023437500 | 0.0093568105415945523190002219848793174605816602706909179687500000 | 0.305383 | 0.0 | 2.823268999999997 | 0.0056920745967741935220085558455593854887410998344421386718750000 | 0.0216513998968292861735385201882309047505259513854980468750000000 | 0.305383 | 6.5e-05 | 2.823268999999999 | 0.0012158900709219858018300675084333306585904210805892944335937500 | 0.0119827414129954849114634285456304496619850397109985351562500000 | 0.357711 | 0.0 | 2.7430479999999964 | 0 | 0 | 0 | 0 |
| 192.168.43.116_52838_152.199.21.118_443_TCP_2022-07-27 18:15:54.171015 | 2022-07-27 14:15:54.171015 | 192.168.43.116 | 52838 | 152.199.21.118 | 443 | TCP | 4.655009 | 1686 | 281 | 1405 | 1935209 | 3671 | 1931538 | 1400 | 0 | 1147.810 | 531.965 | 282987.632 | 1400 | 0 | 1147.810 | 531.965 | 4004.636 | 1400 | 0 | 1147.810 | 531.965 | 29748.193 | 34344 | 32 | 20 | 20.370 | 2.074 | 6232 | 32 | 20 | 22.177 | 4.625 | 28112 | 32 | 20 | 20.008 | 0.320 | 13.064 | 1374.7601423487545 | 1147.8107947805456 | 64240 | 65535 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 415726.15649078233 | 788.6128684176551 | 414937.54362236464 | 362.19049200549347 | 301.82541000457786 | 60.36508200091558 | 5.0 | 713.0 | 5.5 | 24195.737749423104 | 275433.28571428574 | 198.14285714285714 | 2019396.558496036 | 2 | 1426 | 11 | 0.058936 | 7 | 1928033 | 1387 | 0.954757 | 0 | 418 | 0 | 0 | 2 | 1685 | 0 | 0 | 0 | 24 | 0 | 0 | 1 | 280 | 0 | 0 | 0 | 394 | 0 | 0 | 1 | 1405 | 0 | 0 | 0.0027626166172106825930088191967115562874823808670043945312500000 | 0.0454314267416226630347253490072034765034914016723632812500000000 | 1.620274 | 0.0 | 4.655008999999995 | 0.0166250321428571441739752145849706721492111682891845703125000000 | 0.1108640178950371091293192193916183896362781524658203125000000000 | 1.620274 | 5.3e-05 | 4.655008999999995 | 0.0032447108262108263591894097288559351000003516674041748046875000 | 0.0513123862702731040053016897672932827845215797424316406250000000 | 1.641034 | 0.0 | 4.5555739999999965 | 281.0 | 1405.0 | 3671.0 | 3671.0 |
| 192.168.43.116_52775_142.250.184.229_443_TCP_2022-07-27 18:14:06.005934 | 2022-07-27 14:14:06.005934 | 192.168.43.116 | 52775 | 142.250.184.229 | 443 | TCP | 14.783576 | 11 | 5 | 6 | 193 | 64 | 129 | 73 | 0 | 17.545 | 25.542 | 652.429 | 73 | 0 | 17.545 | 25.542 | 255.759 | 73 | 0 | 17.545 | 25.542 | 948.583 | 244 | 32 | 20 | 22.181 | 4.628 | 100 | 20 | 20 | 20 | 0 | 144 | 32 | 20 | 24 | 5.656 | 12.8 | 21.5 | 17.545 | 508 | 374 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 13.055 | 4.329128486910069 | 8.725899606428106 | 0.744068958687668 | 0.40585579564781893 | 0.3382131630398491 | 1.2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 4 | 0 | 0 | 0 | 11 | 0 | 1 | 1 | 2 | 0 | 0 | 0 | 5 | 0 | 1 | 0 | 2 | 0 | 0 | 0 | 6 | 0 | 0 | 1.4783576000000000494338792123016901314258575439453125000000000000 | 4.362392703804786719956609886139631271362304687500 | 14.565012 | 5.4e-05 | 14.783575999999996 | 3.69589400000000001256239556823857128620147705078125 | 6.34482431811752345396371310926042497158050537109375 | 14.685235 | 5.4e-05 | 14.783576 | 2.932655000000000011795009413617663085460662841796875 | 5.81624351910217018968296542880125343799591064453125 | 14.565012 | 0.000331 | 14.663274999999999 | 5.0 | 6.0 | 64.0 | 64.0 |
| 192.168.43.116_52786_172.67.75.39_443_TCP_2022-07-27 18:15:40.490110 | 2022-07-27 14:15:40.490110 | 192.168.43.116 | 52786 | 172.67.75.39 | 443 | TCP | 0.108553 | 3 | 1 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 60 | 20 | 20 | 20 | 0 | 20 | 20 | 20 | 20 | 0 | 40 | 20 | 20 | 20 | 0 | 0.0 | 0.0 | 0.0 | 1020 | 95 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | 27.636 | 18.424 | 9.212 | 2.0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 0 | 3 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 2 | 0 | 0 | 0.054 | 0.0051 | 0.059445 | 0.049108 | 0.108553 | 1658945740.490 | 0 | 1658945740.49011 | 1658945740.49011 | 1658945740.49011 | 0.049 | 0 | 0.049108 | 0.049108 | 0.049108 | 0 | 0 | 0 | 0 |



----


# Copyright (c) 2023

For citation in your works and also understanding NLFlowLyzer completely, you can find below published papers:

????????????????????????????????????????????????????????????


# Contributing

Any contribution is welcome in form of pull requests.


# Project Team members 

* [**Arash Habibi Lashkari:**](http://ahlashkari.com/index.asp) Founder and supervisor

* [**Moein Shafi:**](https://github.com/moein-shafi) Graduate student, Researcher and developer - York University 
  - Approval of All Features' Development
  - Project Management
  - Python Package Management
  - Repository Management
  - Architecture Design
  - Implementation of Base Structure (Architecture), i.e., Development of All Classes and Modules
  - Re-Development of All Features to Match the Architecture
  - Approval of Pull Requests
  - Task Assignment and Management
  - Implementation of Multi-Process Functionality
  - Code Style Improvement
  - Execution of Performance Tests
  - Verification of Output with Wireshark 

* [**Sepideh Niktabe:**](https://github.com/sepideh2020) Graduate students, Researcher and developer - York University (6 months, 2022-2023)
  - Development of All Count-related Features
  - Development of All PayloadBytes-related Features
  - Development of All Flag-related Features
  - Verification of Output with CICFlowMeter's output
  - Identification of CICFlowMeter's shortcomings
  - Dockerfile

* [**Mehrsa Khoshpasand:**](https://github.com/Khoshpasand-mehrsa) Researcher Assistant (RA) - York University (3 months, 2022)
  - Development of Down-Up Ratio Feature
  - Development of All Idle-time-related Features

* [**Parisa Ghanad:**](https://github.com/parishisit) Volunteer Researcher and developer - Amirkabir University (4 months, 2022)
  - Development of All Bulk-related Features
  - Development of All Subflow-related Features
  - Development of All Time-related Features
  - Development of All Rate-related Features
  - Approval of All Features' Development
  - Task Assignment and Management
  - Verification of Output with Wireshark
  - Identification of CICFlowMeter's shortcomings


# Acknowledgment

This project has been made possible through funding from the Natural Sciences and Engineering Research Council of Canada — NSERC (#RGPIN-2020-04701) and Canada Research Chair (Tier II) - (#CRC-2021-00340) to Arash Habibi Lashkari.
