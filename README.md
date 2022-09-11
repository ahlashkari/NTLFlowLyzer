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


| flow_id | timestamp | src_ip | src_port | dst_ip | dst_port | protocol | duration | packets_count | fwd_packets_count | bwd_packets_count | total_payload_bytes | fwd_total_payload_bytes | bwd_total_payload_bytes | payload_bytes_max | payload_bytes_min | payload_bytes_mean | payload_bytes_std | payload_bytes_variance | fwd_payload_bytes_max | fwd_payload_bytes_min | fwd_payload_bytes_mean | fwd_payload_bytes_std | bwd_payload_bytes_max | bwd_payload_bytes_min | bwd_payload_bytes_mean | bwd_payload_bytes_std | bwd_payload_bytes_variance | total_header_bytes | max_header_bytes | min_header_bytes | mean_header_bytes | std_header_bytes | fwd_total_header_bytes | fwd_max_header_bytes | fwd_min_header_bytes | fwd_mean_header_bytes | fwd_std_header_bytes | fwd_avg_segment_size | bwd_avg_segment_size | avg_segment_size | fwd_init_win_bytes | bwd_init_win_bytes | active_min | active_max | active_mean | active_std | idle_min | idle_max | idle_mean | idle_std | bytes_rate | fwd_bytes_rate | bwd_bytes_rate | packets_rate | bwd_packets_rate | fwd_packets_rate | down_up_rate | avg_fwd_bytes_per_bulk | avg_fwd_packets_per_bulk | avg_fwd_bulk_rate | avg_bwd_bytes_per_bulk | avg_bwd_packets_bulk_rate | avg_bwd_bulk_rate | fwd_bulk_state_count | fwd_bulk_total_size | fwd_bulk_per_packet | fwd_bulk_duration | bwd_bulk_state_count | bwd_bulk_total_size | bwd_bulk_per_packet | bwd_bulk_duration | fin_flag_counts | psh_flag_counts | urg_flag_counts | ece_flag_counts | syn_flag_counts | ack_flag_counts | cwr_flag_counts | rst_flag_counts | fwd_fin_flag_counts | fwd_psh_flag_counts | fwd_urg_flag_counts | fwd_ece_flag_counts | fwd_syn_flag_counts | fwd_ack_flag_counts | fwd_cwr_flag_counts | fwd_rst_flag_counts | bwd_fin_flag_counts | bwd_psh_flag_counts | bwd_urg_flag_counts | bwd_ece_flag_counts | bwd_syn_flag_counts | bwd_ack_flag_counts | bwd_cwr_flag_counts | bwd_rst_flag_counts | packets_IAT_mean | packet_IAT_std | packet_IAT_max | packet_IAT_min | packet_IAT_total | fwd_packets_IAT_mean | fwd_packets_IAT_std | fwd_packets_IAT_max | fwd_packets_IAT_min | fwd_packets_IAT_total | bwd_packets_IAT_mean | bwd_packets_IAT_std | bwd_packets_IAT_max | bwd_packets_IAT_min | bwd_packets_IAT_total | subflow_fwd_packets | subflow_bwd_packets | subflow_fwd_bytes | subflow_bwd_bytes |
| :-------------------------------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: | :-------------------------------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: | :-------------------------------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: | :-------------------------------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: | :-------------------------------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: | :-------------------------------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |  :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: | :------------: | :----------------: | :----------------: |  :----------------: |  :----------------: |
| 192.168.116.100_46969_172.217.18.138_443_UDP_2022-04-14 20:30:11.515837 | 2022-04-14 16:30:11.515837 | 192.168.116.100 | 46969 | 172.217.18.138 | 443 | UDP | 1.583172 | 883 | 181 | 702 | 880788 | 16759 | 864029 | 1350 | 25 | 997.4949037372593920736107975244522094726562500000000000000000000000 | 561.3629534350453695878968574106693267822265625000000000000000000000 | 19941.1477671621760237030684947967529296875000000000000000000000000000 | 1350 | 25 | 997.4949037372593920736107975244522094726562500000000000000000000000 | 561.3629534350453695878968574106693267822265625000000000000000000000 | 1350 | 25 | 997.4949037372593920736107975244522094726562500000000000000000000000 | 561.3629534350453695878968574106693267822265625000000000000000000000 | 125673.5096894505695672705769538879394531250000000000000000000000000000 | 7064 | 8 | 8 | 8.0000000000000000000000000000000000000000000000000000000000000000 | 0.0000000000000000000000000000000000000000000000000000000000000000 | 5616 | 8 | 8 | 8.0000000000000000000000000000000000000000000000000000000000000000 | 0.0000000000000000000000000000000000000000000000000000000000000000 | 92.59116022099448 | 1230.8105413105413 | 997.4949037372594 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 556343.8464045599 | 10585.710207103208 | 545758.1361974567 | 557.7410414029556 | 443.41360256497717 | 114.32743883797843 | 3.8784530386740332 | 1165.7777777777778 | 7.333333333333333 | 91889.1934735201 | 13000.65 | 10.416666666666666 | 1667216.6781727364 | 9 | 10492 | 66 | 0.114181 | 60 | 780039 | 625 | 0.467869 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0.0017949795918367347172944770150593285507056862115859985351562500 | 0.0125465779851681256268358666261519829276949167251586914062500000 | 0.222213 | -6e-06 | 1.583171999999999 | 0.0087764999999999995794475182719907024875283241271972656250000000 | 0.0288853940417990485978183556881049298681318759918212890625000000 | 0.246103 | 1.8e-05 | 1.57977 | 0.0021812667617689017116044958299880818231031298637390136718750000 | 0.0151368165583875679408576431228539149742573499679565429687500000 | 0.222213 | 0.0 | 1.5290679999999983 | 0 | 0 | 0 | 0 |
| 192.168.43.116_52765_142.250.186.133_443_TCP_2022-07-27 18:14:04.374890 | 2022-07-27 14:14:04.374890 | 192.168.43.116 | 52765 | 142.250.186.133 | 443 | TCP | 100.345666 | 276 | 91 | 185 | 204871 | 38998 | 165873 | 1400 | 0 | 742.2862318840579973766580224037170410156250000000000000000000000000 | 656.5600251477645770137314684689044952392578125000000000000000000000 | 363470.2035985992406494915485382080078125000000000000000000000000000000 | 1400 | 0 | 742.2862318840579973766580224037170410156250000000000000000000000000 | 656.5600251477645770137314684689044952392578125000000000000000000000 | 1400 | 0 | 742.2862318840579973766580224037170410156250000000000000000000000000 | 656.5600251477645770137314684689044952392578125000000000000000000000 | 392090.0106939371908083558082580566406250000000000000000000000000000000 | 5592 | 32 | 20 | 20.2608695652173906864845775999128818511962890625000000000000000000 | 1.7499662432607050455146691092522814869880676269531250000000000000 | 3772 | 32 | 20 | 20.3891891891891887667043192777782678604125976562500000000000000000 | 2.1257474086279701808166464616078883409500122070312500000000000000 | 428.54945054945057 | 896.6108108108108 | 742.286231884058 | 65527 | 2174 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2041.652700775338 | 388.63661535715954 | 1653.0160854181786 | 2.750492482654906 | 1.8436272075766582 | 0.9068652750782481 | 2.032967032967033 | 7021.666666666667 | 7.0 | 48624.59229439288 | 31408.8 | 25.2 | 258988.2498453927 | 3 | 21065 | 21 | 0.433217 | 5 | 157044 | 126 | 0.606375 | 0 | 114 | 0 | 0 | 0 | 276 | 0 | 0 | 0 | 27 | 0 | 0 | 0 | 91 | 0 | 0 | 0 | 87 | 0 | 0 | 0 | 185 | 0 | 0 | 0.3648933309090909293814775082864798605442047119140625000000000000 | 3.4364095339008131624325415032217279076576232910156250000000000000 | 45.010319 | 0.0 | 100.345666 | 1.1146453555555555503531195427058264613151550292968750000000000000 | 5.9432496691043290582001645816490054130554199218750000000000000000 | 45.046832 | 0.0 | 100.31808199999999 | 0.5450481086956522336350872137700207531452178955078125000000000000 | 4.1926245931902839103599944792222231626510620117187500000000000000 | 45.030952 | 0.0 | 100.28885200000002 | 18.2 | 37.0 | 7799.6 | 7799.6 |
| 192.168.43.116_52790_104.21.69.158_443_TCP_2022-07-27 18:14:08.578480 | 2022-07-27 14:14:08.578480 | 192.168.43.116 | 52790 | 104.21.69.158 | 443 | TCP | 0.343462 | 14 | 6 | 8 | 4846 | 305 | 4541 | 1400 | 0 | 346.1428571428571672186080832034349441528320312500000000000000000000 | 561.3693534745268607366597279906272888183593750000000000000000000000 | 12920.1388888888886867789551615715026855468750000000000000000000000000 | 1400 | 0 | 346.1428571428571672186080832034349441528320312500000000000000000000 | 561.3693534745268607366597279906272888183593750000000000000000000000 | 1400 | 0 | 346.1428571428571672186080832034349441528320312500000000000000000000 | 561.3693534745268607366597279906272888183593750000000000000000000000 | 427336.9843750000000000000000000000000000000000000000000000000000000000 | 304 | 32 | 20 | 21.7142857142857153007753368001431226730346679687500000000000000000 | 4.1991252733425907806008581246715039014816284179687500000000000000 | 172 | 32 | 20 | 21.5000000000000000000000000000000000000000000000000000000000000000 | 3.9686269665968860742566448607249185442924499511718750000000000000 | 50.833333333333336 | 567.625 | 346.14285714285717 | 64240 | 65535 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 14109.27555304517 | 888.0167238297105 | 13221.25882921546 | 40.76142338890474 | 23.292241936516994 | 17.469181452387748 | 1.3333333333333333 | 0 | 0 | 0 | 4541.0 | 4.0 | 1795571.3720838276 | 0 | 0 | 0 | 0 | 1 | 4541 | 4 | 0.002529 | 2 | 3 | 0 | 0 | 2 | 13 | 0 | 0 | 1 | 1 | 0 | 0 | 1 | 5 | 0 | 0 | 1 | 2 | 0 | 0 | 1 | 8 | 0 | 0 | 0.0264201538461538466828759652571534388698637485504150390625000000 | 0.0349830592470702014806782642608595779165625572204589843750000000 | 0.105479 | 9.1e-05 | 0.343462 | 0.0495307999999999998275157508942356798797845840454101562500000000 | 0.0517288412528252999900146846812276635318994522094726562500000000 | 0.119035 | 0.002165 | 0.24765399999999999 | 0.0339975714285714256113202225151326274499297142028808593750000000 | 0.0321096063145201032762443560386600438505411148071289062500000000 | 0.088577 | 0.000417 | 0.237983 | 0 | 0 | 0 | 0  |


----

TODO: complete this part
# Development

Talk about how other people can improve the NetFlowMeter and adding new features.

