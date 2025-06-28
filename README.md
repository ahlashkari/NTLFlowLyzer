# NTLFlowLyzer

As part of the Understanding Cybersecurity Series (UCS), NTLFlowLyzer is a Python open-source project to extract network layer features from TCP-based network traffic for Anomaly Profiling (AP) which is the second component of the [**NetFlowLyzer**](https://github.com/ahlashkari/NetFlowLyzer).

NTLFlowLyzer generates bidirectional flows from the Network and Transportation Layers of network traffic, where the first packet determines the forward (source to destination) and backward (destination to source) directions, hence the statistical time-related features can be calculated separately in the forward and backward directions. Additional functionalities include selecting features from the list of existing features, adding new features, and controlling the duration of flow timeout. Moreover, TCP flows are terminated upon connection teardown (by FIN or RST packet), reaching the flow's maximum duration, or being inactive for a certain amount of time (timeout).

In this updated version (NTLFlowLyzer-V0.3.0), we incorporate advanced entropy-based features for encrypted traffic analysis, significantly enriching the representation of traffic behavior. These new features are detailed under the Extracted Features section.

# Table of Contents

- [NTLFlowLyzer](#ntlflowlyzer)
- [Table of Contents](#table-of-contents)
- [Installation](#installation)
- [Execution](#execution)
- [Architecture](#architecture)
- [Extracted Features](#extracted-features)
  - [New Entropy Features](#new-entropy-features)
  - [Definitions](#definitions)
  - [Statistical Information Calculation](#statistical-information-calculation)
- [Output](#output)
- [Copyright (c) 2023](#copyright-c-2023)
- [Contributing](#contributing)
- [Project Team members](#project-team-members)
- [Acknowledgment](#acknowledgment)

# Installation

Before installing or running the NTLFlowLyzer package, it's essential to set up the necessary requirements on your system. Begin by ensuring you have both `Python` and `pip` installed and functioning properly (execute the `pip3 --version` command). Then, execute the following command:

```bash
pip3 install -r requirements.txt
```

You are prepared to install NTLFlowLyzer. To proceed, execute the following command in the package's root directory (where the setup.py file is located), which will install the NTLFlowLyzer package on your system:

### On Linux:
```bash
python3 setup.py install
```

### On Windows:
```bash
pip3 install .
```

After successfully installing the package, confirm the installation by running the following command:

```bash
ntlflowlyzer --version
```


# Execution

The core aspect of running NTLFlowLyzer involves preparing the configuration file. This file is designed to facilitate users in customizing the program's behavior with minimal complexity and cost, thus enhancing program scalability. Below, we outline how to prepare the configuration file and subsequently demonstrate how to execute NTLFlowLyzer using it.

## Configuration File

The configuration file is formatted in `JSON`, comprising key-value pairs that enable customization of the package. While some keys are mandatory, others are optional. Below, each key is explained along with its corresponding value:

* **pcap_file_address** [Required]
  
  This key specifies the input PCAP file address. The format of the value should be a string.
  
  **Note**: At this version of NTLFlowLyzer, we only support the `PCAP` format. For other formats such as `PCAPNG`, you must convert them to `PCAP`. To convert `PCAPNG` to `PCAP`, you can use Wireshark. If you prefer command-line tools, you can use the following command:

  ```bash
  tshark -F pcap -r {pcapng_file} -w {pcap_file}
  ```

  Replace `{pcapng_file}` with the path to your PCAPNG file and `{pcap_file}` with the desired output PCAP file name.

* **output_file_address** [Required]

  This key specifies the output CSV file address. The format of the value should be a string.

* **label** [Optional]

  This key specifies the value of the `label` column in the output CSV file address. The format of the value should be a string. The default value is `Unknown`.


* **number_of_threads** [Optional]

  This key specifies the number of threads to be used for all processes, including flow extraction, feature calculation, and output writing. The value must be an integer of at least `3`. The default value is `4`.

  It's important to consider that the optimal value for this option varies based on the system configuration and the format of the input PCAP file. For instance, if the PCAP file contains a large number of packets (e.g., more than 5 million) and they are all TCP packets, increasing the number of threads might be beneficial. However, if the packets represent a small number of flows and all related packets are contiguous, adding more threads could potentially slow down the program since there are fewer distinct flows.

  As a rule of thumb, the ideal value for this option typically falls between half the number of CPU cores (CPU count) and twice the CPU count. This helps balance computational resources without overwhelming the system. (`0.5 * cpu_count < best_option < 2 * cpu_count`)


* **feature_extractor_min_flows** [Optional]

  This key determines the minimum number of finished flows required for the feature extractor thread to initiate its work and extract features from these finished flows. The value must be an integer. The default value is `4000`.

  Selecting a high value for this option will consume more RAM since more flows will be stored in memory, potentially slowing down the entire program. Conversely, choosing a low value for this option can slow down the execution process, as it involves locking the finished flows list and then copying those flows for feature extraction. These two processes, locking and copying, are slow and can impede other program components.


* **writer_min_rows** [Optional]

  This key specifies the minimum number of ready flows (i.e., finished flows from which features have been extracted) required for the writer thread to begin its work of writing the flows to the CSV file. The value must be an integer. The default value is `6000`.

  Opting for a high value for this option will increase RAM usage since more flows will be stored in memory, potentially slowing down the overall program performance. Conversely, selecting a low value for this option can slow down the execution process, involving locking the finished flows list, copying those flows for the writing process, and performing I/O operations to write to the file. These three processes — locking, copying, and I/O — are slow and may impede other program components.
  
* **read_packets_count_value_log_info** [Optional]

  This key determines the minimum number of processed packets (i.e., the number of packets read from the PCAP file and assigned to a flow) required for the logger to log. The value must be an integer. The default value is `10,000`. This means that after processing every `10,000` packets, the program will print a statement indicating the number of packets analyzed.


* **check_flows_ending_min_flows** [Optional]

  This key specifies the minimum number of ongoing flows (i.e., created flows that have not yet finished) required for checking if they have reached the timeout or maximum flow time value. The value must be an integer. The default value is `2000`. This indicates that if the number of ongoing flows exceeds `2000`, the program will proceed to check all flows for timeout or maximum flow time.


* **capturer_updating_flows_min_value** [Optional]

  This key determines the minimum number of finished flows required to be added to the queue for feature extraction. The value must be an integer. The default value is `2000`. This means that if the number of finished flows exceeds `2000`, the program will move them to a separate list for the feature extractor.
  

* **max_flow_duration** [Optional]

  This key sets the maximum duration of a flow in seconds. The value must be an integer. The default value is `120,000`. It means if the flow duration exceeds `120,000` seconds, the program will terminate the flow and initiate a new one.


* **activity_timeout** [Optional]

  This key defines the flow activity timeout in seconds. The value must be an integer. The default value is `5000`. It means if `5000` seconds have elapsed since the last packet of the flow, the program will terminate the flow.


* **floating_point_unit** [Optional]

  This key specifies the floating point unit used for the feature extraction process. The value must be in the format: `.[UNIT]f`. The default value is `.4f`. This indicates that the feature values will be rounded to the fourth decimal place.


* **max_rows_number** [Optional]

  This key defines the maximum number of rows in the output CSV file. The value must be an integer. The default value is `900,000`. It means if there are more than `900,000` flows to be written in the CSV file, the program will close the current CSV file and create a new one for the remaining flows.


* **features_ignore_list** [Optional]

  This key specifies the features that you do not want to extract. The value must be a list of string values, where each string represents a feature name. The default value is an empty list. If you include a feature name in this list, the program will skip extracting that feature, and it will not appear in the output CSV file.


An example of a configuration file would be like this:

```json
{
    "pcap_file_address": "/mnt/c/dataset/my_pcap_file.pcap",
    "output_file_address": "./output-of-my_pcap_file.csv",
    "label": "Benign",
    "number_of_threads": 4,
    "feature_extractor_min_flows": 2500,
    "writer_min_rows": 1000,
    "read_packets_count_value_log_info": 1000000,
    "check_flows_ending_min_flows": 20000,
    "capturer_updating_flows_min_value": 5000,
    "max_flow_duration": 120000,
    "activity_timeout": 300,
    "floating_point_unit": ".4f",
    "max_rows_number": 800000,
    "features_ignore_list": ["duration", "src_ip"]
}
```


In general, we recommend adjusting the values of the following options: `number_of_threads`, `feature_extractor_min_flows`, `writer_min_rows`, `check_flows_ending_min_flows`, and `capturer_updating_flows_min_value`, based on your system configuration. This is particularly important if your PCAP file is large (usually more than 4 GB with over 1 million TCP packets), to optimize program efficiency.


## Argument Parser

You can use `-h` to see different options of the program.

To execute NTLFlowLyzer, simply run the following command:

```bash
ntlflowlyzer -c YOUR_CONFIG_FILE
```

Replace `YOUR_CONFIG_FILE` with the path to your configuration file.


Moreover, this project has been successfully tested on Ubuntu 20.04, Ubuntu 22.04, Windows 10, and Windows 11. It should work on other versions of Ubuntu OS (or even Debian OS) as long as your system has the necessary Python3 packages (you can find the required packages listed in the `requirements.txt` file).


# Architecture


![](./Architecture.svg)

                
----

# Extracted Features
This updated version now extracts over 400 features, including new entropy-based metrics designed for detecting encrypted traffic. These entropy metrics capture distribution patterns of:

1. Packet lengths
2. Inter-arrival times (IAT)
3. Payload byte values
4. Header sizes

These additions enhance the ability to profile traffic in the absence of payload inspection.

New Entropy Features

The following entropy-based features have been added:
- PacketLengthEntropy
- HeaderLengthEntropy
- PayloadByteEntropy
- FwdPayloadByteEntropy
- BwdPayloadByteEntropy
- IATEntropy
- FwdIATEntropy
- BwdIATEntropy

These are computed using Shannon entropy over corresponding distributions in the flow.

- DefinitionsEntropy: Measures the randomness or uncertainty in a distribution. Higher values typically indicate encrypted or compressed content.
- IAT: Inter-Arrival Time between packets.
- Bulk: A series of packets with minimal inter-arrival time, treated as a burst.
- Subflow: A directional grouping of packets within the main bidirectional flow.
- Idle: Duration where no packets are transmitted.

Statistical Information Calculation 
Python's statistics module is used to calculate statistical moments. Entropy values are calculated using base-2 logarithmic functions.

We now have 400+ features that are as follows (features' explanation will be added):

1. flow_id
1. src_ip
1. src_port
1. dst_ip
1. dst_port
1. protocol
1. timestamp
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
1. PayloadBytesMedian
1. PayloadBytesSkewness
1. PayloadBytesCov
1. PayloadBytesMode
1. FwdPayloadBytesMax
1. FwdPayloadBytesMin
1. FwdPayloadBytesMean
1. FwdPayloadBytesStd
1. FwdPayloadBytesVariance
1. FwdPayloadBytesMedian
1. FwdPayloadBytesSkewness
1. FwdPayloadBytesCov
1. FwdPayloadBytesMode
1. BwdPayloadBytesMax
1. BwdPayloadBytesMin
1. BwdPayloadBytesMean
1. BwdPayloadBytesStd
1. BwdPayloadBytesVariance
1. BwdPayloadBytesMedian
1. BwdPayloadBytesSkewness
1. BwdPayloadBytesCov
1. BwdPayloadBytesMode
1. TotalHeaderBytes
1. MaxHeaderBytes
1. MinHeaderBytes
1. MeanHeaderBytes
1. StdHeaderBytes
1. MedianHeaderBytes
1. SkewnessHeaderBytes
1. CoVHeaderBytes
1. ModeHeaderBytes
1. VarianceHeaderBytes
1. FwdTotalHeaderBytes
1. FwdMaxHeaderBytes
1. FwdMinHeaderBytes
1. FwdMeanHeaderBytes
1. FwdStdHeaderBytes
1. FwdMedianHeaderBytes
1. FwdSkewnessHeaderBytes
1. FwdCoVHeaderBytes
1. FwdModeHeaderBytes
1. FwdVarianceHeaderBytes
1. BwdTotalHeaderBytes
1. BwdMaxHeaderBytes
1. BwdMinHeaderBytes
1. BwdMeanHeaderBytes
1. BwdStdHeaderBytes
1. BwdMedianHeaderBytes
1. BwdSkewnessHeaderBytes
1. BwdCoVHeaderBytes
1. BwdModeHeaderBytes
1. BwdVarianceHeaderBytes
1. FwdSegmentSizeMean
1. FwdSegmentSizeMax
1. FwdSegmentSizeMin
1. FwdSegmentSizeStd
1. FwdSegmentSizeVariance
1. FwdSegmentSizeMedian
1. FwdSegmentSizeSkewness
1. FwdSegmentSizeCov
1. FwdSegmentSizeMode
1. BwdSegmentSizeMean
1. BwdSegmentSizeMax
1. BwdSegmentSizeMin
1. BwdSegmentSizeStd
1. BwdSegmentSizeVariance
1. BwdSegmentSizeMedian
1. BwdSegmentSizeSkewness
1. BwdSegmentSizeCov
1. BwdSegmentSizeMode
1. SegmentSizeMean
1. SegmentSizeMax
1. SegmentSizeMin
1. SegmentSizeStd
1. SegmentSizeVariance
1. SegmentSizeMedian
1. SegmentSizeSkewness
1. SegmentSizeCov
1. SegmentSizeMode
1. FwdInitWinBytes
1. BwdInitWinBytes
1. ActiveMin
1. ActiveMax
1. ActiveMean
1. ActiveStd
1. ActiveMedian
1. ActiveSkewness
1. ActiveCoV
1. ActiveMode
1. ActiveVariance
1. IdleMin
1. IdleMax
1. IdleMean
1. IdleStd
1. IdleMedian
1. IdleSkewness
1. IdleCoV
1. IdleMode
1. IdleVariance
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
1. FINFlagPercentageInTotal
1. PSHFlagPercentageInTotal
1. URGFlagPercentageInTotal
1. ECEFlagPercentageInTotal
1. SYNFlagPercentageInTotal
1. ACKFlagPercentageInTotal
1. CWRFlagPercentageInTotal
1. RSTFlagPercentageInTotal
1. FwdFINFlagPercentageInTotal
1. FwdPSHFlagPercentageInTotal
1. FwdURGFlagPercentageInTotal
1. FwdECEFlagPercentageInTotal
1. FwdSYNFlagPercentageInTotal
1. FwdACKFlagPercentageInTotal
1. FwdCWRFlagPercentageInTotal
1. FwdRSTFlagPercentageInTotal
1. BwdFINFlagPercentageInTotal
1. BwdPSHFlagPercentageInTotal
1. BwdURGFlagPercentageInTotal
1. BwdECEFlagPercentageInTotal
1. BwdSYNFlagPercentageInTotal
1. BwdACKFlagPercentageInTotal
1. BwdCWRFlagPercentageInTotal
1. BwdRSTFlagPercentageInTotal
1. FwdFINFlagPercentageInFwdPackets
1. FwdPSHFlagPercentageInFwdPackets
1. FwdURGFlagPercentageInFwdPackets
1. FwdECEFlagPercentageInFwdPackets
1. FwdSYNFlagPercentageInFwdPackets
1. FwdACKFlagPercentageInFwdPackets
1. FwdCWRFlagPercentageInFwdPackets
1. FwdRSTFlagPercentageInFwdPackets
1. BwdFINFlagPercentageInBwdPackets
1. BwdPSHFlagPercentageInBwdPackets
1. BwdURGFlagPercentageInBwdPackets
1. BwdECEFlagPercentageInBwdPackets
1. BwdSYNFlagPercentageInBwdPackets
1. BwdACKFlagPercentageInBwdPackets
1. BwdCWRFlagPercentageInBwdPackets
1. BwdRSTFlagPercentageInBwdPackets
1. PacketsIATMean
1. PacketsIATStd
1. PacketsIATMax
1. PacketsIATMin
1. PacketsIATSum
1. PacketsIATMedian
1. PacketsIATSkewness
1. PacketsIATCoV
1. PacketsIATMode
1. PacketsIATVariance
1. FwdPacketsIATMean
1. FwdPacketsIATStd
1. FwdPacketsIATMax
1. FwdPacketsIATMin
1. FwdPacketsIATSum
1. FwdPacketsIATMedian
1. FwdPacketsIATSkewness
1. FwdPacketsIATCoV
1. FwdPacketsIATMode
1. FwdPacketsIATVariance
1. BwdPacketsIATMean
1. BwdPacketsIATStd
1. BwdPacketsIATMax
1. BwdPacketsIATMin
1. BwdPacketsIATSum
1. BwdPacketsIATMedian
1. BwdPacketsIATSkewness
1. BwdPacketsIATCoV
1. BwdPacketsIATMode
1. BwdPacketsIATVariance
1. SubflowFwdPackets
1. SubflowBwdPackets
1. SubflowFwdBytes
1. SubflowBwdBytes
1. DeltaStart
1. HandshakeDuration
1. HandshakeState
1. PacketsDeltaTimeMin
1. PacketsDeltaTimeMax
1. PacketsDeltaTimeMean
1. PacketsDeltaTimeMode
1. PacketsDeltaTimeVariance
1. PacketsDeltaTimeStd
1. PacketsDeltaTimeMedian
1. PacketsDeltaTimeSkewness
1. PacketsDeltaTimeCoV
1. BwdPacketsDeltaTimeMin
1. BwdPacketsDeltaTimeMax
1. BwdPacketsDeltaTimeMean
1. BwdPacketsDeltaTimeMode
1. BwdPacketsDeltaTimeVariance
1. BwdPacketsDeltaTimeStd
1. BwdPacketsDeltaTimeMedian
1. BwdPacketsDeltaTimeSkewness
1. BwdPacketsDeltaTimeCoV
1. FwdPacketsDeltaTimeMin
1. FwdPacketsDeltaTimeMax
1. FwdPacketsDeltaTimeMean
1. FwdPacketsDeltaTimeMode
1. FwdPacketsDeltaTimeVariance
1. FwdPacketsDeltaTimeStd
1. FwdPacketsDeltaTimeMedian
1. FwdPacketsDeltaTimeSkewness
1. FwdPacketsDeltaTimeCoV
1. PacketsDeltaLenMin
1. PacketsDeltaLenMax
1. PacketsDeltaLenMean
1. PacketsDeltaLenMode
1. PacketsDeltaLenVariance
1. PacketsDeltaLenStd
1. PacketsDeltaLenMedian
1. PacketsDeltaLenSkewness
1. PacketsDeltaLenCoV
1. BwdPacketsDeltaLenMin
1. BwdPacketsDeltaLenMax
1. BwdPacketsDeltaLenMean
1. BwdPacketsDeltaLenMode
1. BwdPacketsDeltaLenVariance
1. BwdPacketsDeltaLenStd
1. BwdPacketsDeltaLenMedian
1. BwdPacketsDeltaLenSkewness
1. BwdPacketsDeltaLenCoV
1. FwdPacketsDeltaLenMin
1. FwdPacketsDeltaLenMax
1. FwdPacketsDeltaLenMean
1. FwdPacketsDeltaLenMode
1. FwdPacketsDeltaLenVariance
1. FwdPacketsDeltaLenStd
1. FwdPacketsDeltaLenMedian
1. FwdPacketsDeltaLenSkewness
1. FwdPacketsDeltaLenCoV
1. HeaderBytesDeltaLenMin
1. HeaderBytesDeltaLenMax
1. HeaderBytesDeltaLenMean
1. HeaderBytesDeltaLenMode
1. HeaderBytesDeltaLenVariance
1. HeaderBytesDeltaLenStd
1. HeaderBytesDeltaLenMedian
1. HeaderBytesDeltaLenSkewness
1. HeaderBytesDeltaLenCoV
1. BwdHeaderBytesDeltaLenMin
1. BwdHeaderBytesDeltaLenMax
1. BwdHeaderBytesDeltaLenMean
1. BwdHeaderBytesDeltaLenMode
1. BwdHeaderBytesDeltaLenVariance
1. BwdHeaderBytesDeltaLenStd
1. BwdHeaderBytesDeltaLenMedian
1. BwdHeaderBytesDeltaLenSkewness
1. BwdHeaderBytesDeltaLenCoV
1. FwdHeaderBytesDeltaLenMin
1. FwdHeaderBytesDeltaLenMax
1. FwdHeaderBytesDeltaLenMean
1. FwdHeaderBytesDeltaLenMode
1. FwdHeaderBytesDeltaLenVariance
1. FwdHeaderBytesDeltaLenStd
1. FwdHeaderBytesDeltaLenMedian
1. FwdHeaderBytesDeltaLenSkewness
1. FwdHeaderBytesDeltaLenCoV
1. PayloadBytesDeltaLenMin
1. PayloadBytesDeltaLenMax
1. PayloadBytesDeltaLenMean
1. PayloadBytesDeltaLenMode
1. PayloadBytesDeltaLenVariance
1. PayloadBytesDeltaLenStd
1. PayloadBytesDeltaLenMedian
1. PayloadBytesDeltaLenSkewness
1. PayloadBytesDeltaLenCoV
1. BwdPayloadBytesDeltaLenMin
1. BwdPayloadBytesDeltaLenMax
1. BwdPayloadBytesDeltaLenMean
1. BwdPayloadBytesDeltaLenMode
1. BwdPayloadBytesDeltaLenVariance
1. BwdPayloadBytesDeltaLenStd
1. BwdPayloadBytesDeltaLenMedian
1. BwdPayloadBytesDeltaLenSkewness
1. BwdPayloadBytesDeltaLenCoV
1. FwdPayloadBytesDeltaLenMin
1. FwdPayloadBytesDeltaLenMax
1. FwdPayloadBytesDeltaLenMean
1. FwdPayloadBytesDeltaLenMode
1. FwdPayloadBytesDeltaLenVariance
1. FwdPayloadBytesDeltaLenStd
1. FwdPayloadBytesDeltaLenMedian
1. FwdPayloadBytesDeltaLenSkewness
1. FwdPayloadBytesDeltaLenCoV

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


Nine mathematical functions are used to extract different features. You can see how those functions are calculated in the NTLFlowLyzer below:

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

|flow_id                                                               |timestamp                 |src_ip        |src_port|dst_ip        |dst_port|protocol|duration              |packets_count|fwd_packets_count|bwd_packets_count|total_payload_bytes|fwd_total_payload_bytes|bwd_total_payload_bytes|payload_bytes_max|payload_bytes_min|payload_bytes_mean|payload_bytes_std|payload_bytes_variance|payload_bytes_median|payload_bytes_skewness|payload_bytes_cov|payload_bytes_mode|fwd_payload_bytes_max|fwd_payload_bytes_min|fwd_payload_bytes_mean|fwd_payload_bytes_std|fwd_payload_bytes_variance|fwd_payload_bytes_median|fwd_payload_bytes_skewness|fwd_payload_bytes_cov|fwd_payload_bytes_mode|bwd_payload_bytes_max|bwd_payload_bytes_min|bwd_payload_bytes_mean|bwd_payload_bytes_std|bwd_payload_bytes_variance|bwd_payload_bytes_median|bwd_payload_bytes_skewness|bwd_payload_bytes_cov|bwd_payload_bytes_mode|total_header_bytes|max_header_bytes|min_header_bytes|mean_header_bytes|std_header_bytes|median_header_bytes|skewness_header_bytes|cov_header_bytes|mode_header_bytes|variance_header_bytes|fwd_total_header_bytes|fwd_max_header_bytes|fwd_min_header_bytes|fwd_mean_header_bytes|fwd_std_header_bytes|fwd_median_header_bytes|fwd_skewness_header_bytes|fwd_cov_header_bytes|fwd_mode_header_bytes|fwd_variance_header_bytes|bwd_total_header_bytes|bwd_max_header_bytes|bwd_min_header_bytes|bwd_mean_header_bytes|bwd_std_header_bytes|bwd_median_header_bytes|bwd_skewness_header_bytes|bwd_cov_header_bytes|bwd_mode_header_bytes|bwd_variance_header_bytes|fwd_segment_size_mean|fwd_segment_size_max|fwd_segment_size_min|fwd_segment_size_std|fwd_segment_size_variance|fwd_segment_size_median|fwd_segment_size_skewness|fwd_segment_size_cov|fwd_segment_size_mode|bwd_segment_size_mean|bwd_segment_size_max|bwd_segment_size_min|bwd_segment_size_std|bwd_segment_size_variance|bwd_segment_size_median|bwd_segment_size_skewness|bwd_segment_size_cov|bwd_segment_size_mode|segment_size_mean|segment_size_max|segment_size_min|segment_size_std|segment_size_variance|segment_size_median|segment_size_skewness|segment_size_cov|segment_size_mode|fwd_init_win_bytes|bwd_init_win_bytes|active_min         |active_max         |active_mean|active_std|active_median|active_skewness|active_cov|active_mode|active_variance|idle_min          |idle_max          |idle_mean|idle_std|idle_median|idle_skewness|idle_cov|idle_mode|idle_variance|bytes_rate        |fwd_bytes_rate      |bwd_bytes_rate    |packets_rate       |bwd_packets_rate   |fwd_packets_rate   |down_up_rate      |avg_fwd_bytes_per_bulk|avg_fwd_packets_per_bulk|avg_fwd_bulk_rate |avg_bwd_bytes_per_bulk|avg_bwd_packets_bulk_rate|avg_bwd_bulk_rate |fwd_bulk_state_count|fwd_bulk_total_size|fwd_bulk_per_packet|fwd_bulk_duration     |bwd_bulk_state_count|bwd_bulk_total_size|bwd_bulk_per_packet|bwd_bulk_duration  |fin_flag_counts|psh_flag_counts|urg_flag_counts|ece_flag_counts|syn_flag_counts|ack_flag_counts|cwr_flag_counts|rst_flag_counts|fwd_fin_flag_counts|fwd_psh_flag_counts|fwd_urg_flag_counts|fwd_ece_flag_counts|fwd_syn_flag_counts|fwd_ack_flag_counts|fwd_cwr_flag_counts|fwd_rst_flag_counts|bwd_fin_flag_counts|bwd_psh_flag_counts|bwd_urg_flag_counts|bwd_ece_flag_counts|bwd_syn_flag_counts|bwd_ack_flag_counts|bwd_cwr_flag_counts|bwd_rst_flag_counts|fin_flag_percentage_in_total|psh_flag_percentage_in_total|urg_flag_percentage_in_total|ece_flag_percentage_in_total|syn_flag_percentage_in_total|ack_flag_percentage_in_total|cwr_flag_percentage_in_total|rst_flag_percentage_in_total|fwd_fin_flag_percentage_in_total|fwd_psh_flag_percentage_in_total|fwd_urg_flag_percentage_in_total|fwd_ece_flag_percentage_in_total|fwd_syn_flag_percentage_in_total|fwd_ack_flag_percentage_in_total|fwd_cwr_flag_percentage_in_total|fwd_rst_flag_percentage_in_total|bwd_fin_flag_percentage_in_total|bwd_psh_flag_percentage_in_total|bwd_urg_flag_percentage_in_total|bwd_ece_flag_percentage_in_total|bwd_syn_flag_percentage_in_total|bwd_ack_flag_percentage_in_total|bwd_cwr_flag_percentage_in_total|bwd_rst_flag_percentage_in_total|fwd_fin_flag_percentage_in_fwd_packets|fwd_psh_flag_percentage_in_fwd_packets|fwd_urg_flag_percentage_in_fwd_packets|fwd_ece_flag_percentage_in_fwd_packets|fwd_syn_flag_percentage_in_fwd_packets|fwd_ack_flag_percentage_in_fwd_packets|fwd_cwr_flag_percentage_in_fwd_packets|fwd_rst_flag_percentage_in_fwd_packets|bwd_fin_flag_percentage_in_bwd_packets|bwd_psh_flag_percentage_in_bwd_packets|bwd_urg_flag_percentage_in_bwd_packets|bwd_ece_flag_percentage_in_bwd_packets|bwd_syn_flag_percentage_in_bwd_packets|bwd_ack_flag_percentage_in_bwd_packets|bwd_cwr_flag_percentage_in_bwd_packets|bwd_rst_flag_percentage_in_bwd_packets|packets_IAT_mean|packet_IAT_std|packet_IAT_max        |packet_IAT_min        |packet_IAT_total      |packets_IAT_median|packets_IAT_skewness|packets_IAT_cov|packets_IAT_mode|packets_IAT_variance|fwd_packets_IAT_mean|fwd_packets_IAT_std|fwd_packets_IAT_max   |fwd_packets_IAT_min   |fwd_packets_IAT_total |fwd_packets_IAT_median|fwd_packets_IAT_skewness|fwd_packets_IAT_cov|fwd_packets_IAT_mode|fwd_packets_IAT_variance|bwd_packets_IAT_mean|bwd_packets_IAT_std|bwd_packets_IAT_max   |bwd_packets_IAT_min   |bwd_packets_IAT_total |bwd_packets_IAT_median|bwd_packets_IAT_skewness|bwd_packets_IAT_cov|bwd_packets_IAT_mode|bwd_packets_IAT_variance|subflow_fwd_packets|subflow_bwd_packets|subflow_fwd_bytes|subflow_bwd_bytes|delta_start             |handshake_duration      |handshake_state|min_bwd_packets_delta_time|max_bwd_packets_delta_time|mean_packets_delta_time|mode_packets_delta_time|variance_packets_delta_time|std_packets_delta_time|median_packets_delta_time|skewness_packets_delta_time|cov_packets_delta_time|mean_bwd_packets_delta_time|mode_bwd_packets_delta_time|variance_bwd_packets_delta_time|std_bwd_packets_delta_time|median_bwd_packets_delta_time|skewness_bwd_packets_delta_time|cov_bwd_packets_delta_time|min_fwd_packets_delta_time|max_fwd_packets_delta_time|mean_fwd_packets_delta_time|mode_fwd_packets_delta_time|variance_fwd_packets_delta_time|std_fwd_packets_delta_time|median_fwd_packets_delta_time|skewness_fwd_packets_delta_time|cov_fwd_packets_delta_time|min_packets_delta_len|max_packets_delta_len|mean_packets_delta_len|mode_packets_delta_len|variance_packets_delta_len|std_packets_delta_len|median_packets_delta_len|skewness_packets_delta_len|cov_packets_delta_len|min_bwd_packets_delta_len|max_bwd_packets_delta_len|mean_bwd_packets_delta_len|mode_bwd_packets_delta_len|variance_bwd_packets_delta_len|std_bwd_packets_delta_len|median_bwd_packets_delta_len|skewness_bwd_packets_delta_len|cov_bwd_packets_delta_len|min_fwd_packets_delta_len|max_fwd_packets_delta_len|mean_fwd_packets_delta_len|mode_fwd_packets_delta_len|variance_fwd_packets_delta_len|std_fwd_packets_delta_len|median_fwd_packets_delta_len|skewness_fwd_packets_delta_len|cov_fwd_packets_delta_len|min_header_bytes_delta_len|max_header_bytes_delta_len|mean_header_bytes_delta_len|mode_header_bytes_delta_len|variance_header_bytes_delta_len|std_header_bytes_delta_len|median_header_bytes_delta_len|skewness_header_bytes_delta_len|cov_header_bytes_delta_len|min_bwd_header_bytes_delta_len|max_bwd_header_bytes_delta_len|mean_bwd_header_bytes_delta_len|mode_bwd_header_bytes_delta_len|variance_bwd_header_bytes_delta_len|std_bwd_header_bytes_delta_len|median_bwd_header_bytes_delta_len|skewness_bwd_header_bytes_delta_len|cov_bwd_header_bytes_delta_len|min_fwd_header_bytes_delta_len|max_fwd_header_bytes_delta_len|mean_fwd_header_bytes_delta_len|mode_fwd_header_bytes_delta_len|variance_fwd_header_bytes_delta_len|std_fwd_header_bytes_delta_len|median_fwd_header_bytes_delta_len|skewness_fwd_header_bytes_delta_len|cov_fwd_header_bytes_delta_len|min_payload_bytes_delta_len|max_payload_bytes_delta_len|mean_payload_bytes_delta_len|mode_payload_bytes_delta_len|variance_payload_bytes_delta_len|std_payload_bytes_delta_len|median_payload_bytes_delta_len|skewness_payload_bytes_delta_len|cov_payload_bytes_delta_len|min_bwd_payload_bytes_delta_len|max_bwd_payload_bytes_delta_len|mean_bwd_payload_bytes_delta_len|mode_bwd_payload_bytes_delta_len|variance_bwd_payload_bytes_delta_len|std_bwd_payload_bytes_delta_len|median_bwd_payload_bytes_delta_len|skewness_bwd_payload_bytes_delta_len|cov_bwd_payload_bytes_delta_len|min_fwd_payload_bytes_delta_len|max_fwd_payload_bytes_delta_len|mean_fwd_payload_bytes_delta_len|mode_fwd_payload_bytes_delta_len|variance_fwd_payload_bytes_delta_len|std_fwd_payload_bytes_delta_len|median_fwd_payload_bytes_delta_len|skewness_fwd_payload_bytes_delta_len|cov_fwd_payload_bytes_delta_len|bin_min_entropy   |hex_min_entropy   |utf8_min_entropy  |mean_per16bytes_bientropy|mean_per32bytes_bientropy|mean_per64bytes_mutual_information|mode_per64bytes_mutual_information|std_per64bytes_mutual_information|median_per64bytes_mutual_information|cov_per64bytes_mutual_information|skewness_per64bytes_mutual_information|mean_binary_per4bytes_entropy|std_binary_per4bytes_entropy|skewness_binary_per4bytes_entropy|mode_binary_per4bytes_entropy|median_binary_per4bytes_entropy|cov_binary_per4bytes_entropy|mean_binary_per8bytes_entropy|std_binary_per8bytes_entropy|skewness_binary_per8bytes_entropy|mode_binary_per8bytes_entropy|median_binary_per8bytes_entropy|cov_binary_per8bytes_entropy|mean_binary_per16bytes_entropy|std_binary_per16bytes_entropy|skewness_binary_per16bytes_entropy|mode_binary_per16bytes_entropy|median_binary_per16bytes_entropy|cov_binary_per16bytes_entropy|mean_binary_per32bytes_entropy|std_binary_per32bytes_entropy|skewness_binary_per32bytes_entropy|mode_binary_per32bytes_entropy|median_binary_per32bytes_entropy|cov_binary_per32bytes_entropy|mean_binary_per64bytes_entropy|std_binary_per64bytes_entropy|skewness_binary_per64bytes_entropy|mode_binary_per64bytes_entropy|median_binary_per64bytes_entropy|cov_binary_per64bytes_entropy|mean_hex_per4bytes_entropy|std_hex_per4bytes_entropy|skewness_hex_per4bytes_entropy|mode_hex_per4bytes_entropy|median_hex_per4bytes_entropy|cov_hex_per4bytes_entropy|mean_hex_per8bytes_entropy|std_hex_per8bytes_entropy|skewness_hex_per8bytes_entropy|mode_hex_per8bytes_entropy|median_hex_per8bytes_entropy|cov_hex_per8bytes_entropy|mean_hex_per16bytes_entropy|std_hex_per16bytes_entropy|skewness_hex_per16bytes_entropy|mode_hex_per16bytes_entropy|median_hex_per16bytes_entropy|cov_hex_per16bytes_entropy|mean_hex_per32bytes_entropy|std_hex_per32bytes_entropy|skewness_hex_per32bytes_entropy|mode_hex_per32bytes_entropy|median_hex_per32bytes_entropy|cov_hex_per32bytes_entropy|mean_hex_per64bytes_entropy|std_hex_per64bytes_entropy|skewness_hex_per64bytes_entropy|mode_hex_per64bytes_entropy|median_hex_per64bytes_entropy|cov_hex_per64bytes_entropy|mean_utf8_per4bytes_entropy|std_utf8_per4bytes_entropy|skewness_utf8_per4bytes_entropy|mode_utf8_per4bytes_entropy|median_utf8_per4bytes_entropy|cov_utf8_per4bytes_entropy|mean_utf8_per8bytes_entropy|std_utf8_per8bytes_entropy|skewness_utf8_per8bytes_entropy|mode_utf8_per8bytes_entropy|median_utf8_per8bytes_entropy|cov_utf8_per8bytes_entropy|mean_utf8_per16bytes_entropy|std_utf8_per16bytes_entropy|skewness_utf8_per16bytes_entropy|mode_utf8_per16bytes_entropy|median_utf8_per16bytes_entropy|cov_utf8_per16bytes_entropy|mean_utf8_per32bytes_entropy|std_utf8_per32bytes_entropy|skewness_utf8_per32bytes_entropy|mode_utf8_per32bytes_entropy|median_utf8_per32bytes_entropy|cov_utf8_per32bytes_entropy|mean_utf8_per64bytes_entropy|std_utf8_per64bytes_entropy|skewness_utf8_per64bytes_entropy|mode_utf8_per64bytes_entropy|median_utf8_per64bytes_entropy|cov_utf8_per64bytes_entropy|binary_2_gram_entropy|binary_3_gram_entropy|binary_4_gram_entropy|binary_5_gram_entropy|binary_6_gram_entropy|binary_7_gram_entropy|binary_8_gram_entropy|binary_9_gram_entropy|binary_10_gram_entropy|hex_2_gram_entropy    |hex_3_gram_entropy    |hex_4_gram_entropy   |hex_5_gram_entropy    |hex_6_gram_entropy    |hex_7gram_entropy     |hex_8_gram_entropy    |hex_9_gram_entropy    |hex_10_gram_entropy   |utf8_2_gram_entropy |utf8_3_gram_entropy  |utf8_4_gram_entropy  |utf8_5_gram_entropy   |utf8_6_gram_entropy  |utf8_7_gram_entropy   |utf8_8_gram_entropy  |utf8_9_gram_entropy   |utf8_10_gram_entropy  |label  |
|----------------------------------------------------------------------|--------------------------|--------------|--------|--------------|--------|--------|----------------------|-------------|-----------------|-----------------|-------------------|-----------------------|-----------------------|-----------------|-----------------|------------------|-----------------|----------------------|--------------------|----------------------|-----------------|------------------|---------------------|---------------------|----------------------|---------------------|--------------------------|------------------------|--------------------------|---------------------|----------------------|---------------------|---------------------|----------------------|---------------------|--------------------------|------------------------|--------------------------|---------------------|----------------------|------------------|----------------|----------------|-----------------|----------------|-------------------|---------------------|----------------|-----------------|---------------------|----------------------|--------------------|--------------------|---------------------|--------------------|-----------------------|-------------------------|--------------------|---------------------|-------------------------|----------------------|--------------------|--------------------|---------------------|--------------------|-----------------------|-------------------------|--------------------|---------------------|-------------------------|---------------------|--------------------|--------------------|--------------------|-------------------------|-----------------------|-------------------------|--------------------|---------------------|---------------------|--------------------|--------------------|--------------------|-------------------------|-----------------------|-------------------------|--------------------|---------------------|-----------------|----------------|----------------|----------------|---------------------|-------------------|---------------------|----------------|-----------------|------------------|------------------|-------------------|-------------------|-----------|----------|-------------|---------------|----------|-----------|---------------|------------------|------------------|---------|--------|-----------|-------------|--------|---------|-------------|------------------|--------------------|------------------|-------------------|-------------------|-------------------|------------------|----------------------|------------------------|------------------|----------------------|-------------------------|------------------|--------------------|-------------------|-------------------|----------------------|--------------------|-------------------|-------------------|-------------------|---------------|---------------|---------------|---------------|---------------|---------------|---------------|---------------|-------------------|-------------------|-------------------|-------------------|-------------------|-------------------|-------------------|-------------------|-------------------|-------------------|-------------------|-------------------|-------------------|-------------------|-------------------|-------------------|----------------------------|----------------------------|----------------------------|----------------------------|----------------------------|----------------------------|----------------------------|----------------------------|--------------------------------|--------------------------------|--------------------------------|--------------------------------|--------------------------------|--------------------------------|--------------------------------|--------------------------------|--------------------------------|--------------------------------|--------------------------------|--------------------------------|--------------------------------|--------------------------------|--------------------------------|--------------------------------|--------------------------------------|--------------------------------------|--------------------------------------|--------------------------------------|--------------------------------------|--------------------------------------|--------------------------------------|--------------------------------------|--------------------------------------|--------------------------------------|--------------------------------------|--------------------------------------|--------------------------------------|--------------------------------------|--------------------------------------|--------------------------------------|----------------|--------------|----------------------|----------------------|----------------------|------------------|--------------------|---------------|----------------|--------------------|--------------------|-------------------|----------------------|----------------------|----------------------|----------------------|------------------------|-------------------|--------------------|------------------------|--------------------|-------------------|----------------------|----------------------|----------------------|----------------------|------------------------|-------------------|--------------------|------------------------|-------------------|-------------------|-----------------|-----------------|------------------------|------------------------|---------------|--------------------------|--------------------------|-----------------------|-----------------------|---------------------------|----------------------|-------------------------|---------------------------|----------------------|---------------------------|---------------------------|-------------------------------|--------------------------|-----------------------------|-------------------------------|--------------------------|--------------------------|--------------------------|---------------------------|---------------------------|-------------------------------|--------------------------|-----------------------------|-------------------------------|--------------------------|---------------------|---------------------|----------------------|----------------------|--------------------------|---------------------|------------------------|--------------------------|---------------------|-------------------------|-------------------------|--------------------------|--------------------------|------------------------------|-------------------------|----------------------------|------------------------------|-------------------------|-------------------------|-------------------------|--------------------------|--------------------------|------------------------------|-------------------------|----------------------------|------------------------------|-------------------------|--------------------------|--------------------------|---------------------------|---------------------------|-------------------------------|--------------------------|-----------------------------|-------------------------------|--------------------------|------------------------------|------------------------------|-------------------------------|-------------------------------|-----------------------------------|------------------------------|---------------------------------|-----------------------------------|------------------------------|------------------------------|------------------------------|-------------------------------|-------------------------------|-----------------------------------|------------------------------|---------------------------------|-----------------------------------|------------------------------|---------------------------|---------------------------|----------------------------|----------------------------|--------------------------------|---------------------------|------------------------------|--------------------------------|---------------------------|-------------------------------|-------------------------------|--------------------------------|--------------------------------|------------------------------------|-------------------------------|----------------------------------|------------------------------------|-------------------------------|-------------------------------|-------------------------------|--------------------------------|--------------------------------|------------------------------------|-------------------------------|----------------------------------|------------------------------------|-------------------------------|------------------|------------------|------------------|-------------------------|-------------------------|----------------------------------|----------------------------------|---------------------------------|------------------------------------|---------------------------------|--------------------------------------|-----------------------------|----------------------------|---------------------------------|-----------------------------|-------------------------------|----------------------------|-----------------------------|----------------------------|---------------------------------|-----------------------------|-------------------------------|----------------------------|------------------------------|-----------------------------|----------------------------------|------------------------------|--------------------------------|-----------------------------|------------------------------|-----------------------------|----------------------------------|------------------------------|--------------------------------|-----------------------------|------------------------------|-----------------------------|----------------------------------|------------------------------|--------------------------------|-----------------------------|--------------------------|-------------------------|------------------------------|--------------------------|----------------------------|-------------------------|--------------------------|-------------------------|------------------------------|--------------------------|----------------------------|-------------------------|---------------------------|--------------------------|-------------------------------|---------------------------|-----------------------------|--------------------------|---------------------------|--------------------------|-------------------------------|---------------------------|-----------------------------|--------------------------|---------------------------|--------------------------|-------------------------------|---------------------------|-----------------------------|--------------------------|---------------------------|--------------------------|-------------------------------|---------------------------|-----------------------------|--------------------------|---------------------------|--------------------------|-------------------------------|---------------------------|-----------------------------|--------------------------|----------------------------|---------------------------|--------------------------------|----------------------------|------------------------------|---------------------------|----------------------------|---------------------------|--------------------------------|----------------------------|------------------------------|---------------------------|----------------------------|---------------------------|--------------------------------|----------------------------|------------------------------|---------------------------|---------------------|---------------------|---------------------|---------------------|---------------------|---------------------|---------------------|---------------------|----------------------|----------------------|----------------------|---------------------|----------------------|----------------------|----------------------|----------------------|----------------------|----------------------|--------------------|---------------------|---------------------|----------------------|---------------------|----------------------|---------------------|----------------------|----------------------|-------|
|216.58.220.131_443_172.24.216.110_52478_TCP_2020-04-16 03:55:23.984763|2020-04-16 03:55:23.984763|216.58.220.131|443     |172.24.216.110|52478   |TCP     |0.00026297569274902344|4            |2                |2                |56                 |56                     |0                      |56               |0                |14.0000           |24.2487          |588.0000              |0.0000              |1.1547                |1.7321           |0.0000            |56                   |0                    |14.0000               |24.2487              |784.0000                  |28.0000                 |0.0000                    |1.0000               |0.0000                |56                   |0                    |14.0000               |24.2487              |0.0000                    |0.0000                  |nan                       |nan                  |0.0000                |80                |20              |20              |20.0000          |0.0000          |20.0000            |nan                  |0.0000          |20.0000          |0.0000               |40                    |20                  |20                  |20.0000              |0.0000              |20.0000                |nan                      |0.0000              |20.0000              |0.0000                   |40                    |20                  |20                  |20.0000              |0.0000              |20.0000                |nan                      |0.0000              |20.0000              |0.0000                   |48.0000              |76                  |20                  |28.0000             |784.0000                 |48.0000                |0.0000                   |0.5833              |20.0000              |20.0000              |20                  |20                  |0.0000              |0.0000                   |20.0000                |nan                      |0.0000              |20.0000              |34.0000          |76              |20              |24.2487         |588.0000             |20.0000            |1.1547               |0.7132          |20.0000          |246               |8193              |0                  |0                  |0          |0         |0            |0              |0         |0          |0              |0                 |0                 |0        |0       |0          |0            |0       |0        |0            |212947.4378966455 |212947.4378966455   |0.0               |15210.531278331822 |7605.265639165911  |7605.265639165911  |1.0               |0                     |0                       |0                 |0                     |0                        |0                 |0                   |0                  |0                  |0                     |0                   |0                  |0                  |0                  |2              |1              |0              |0              |0              |4              |0              |0              |1                  |1                  |0                  |0                  |0                  |2                  |0                  |0                  |1                  |0                  |0                  |0                  |0                  |2                  |0                  |0                  |0.5                         |0.25                        |0.0                         |0.0                         |0.0                         |1.0                         |0.0                         |0.0                         |0.25                            |0.25                            |0.0                             |0.0                             |0.0                             |0.5                             |0.0                             |0.0                             |0.25                            |0.0                             |0.0                             |0.0                             |0.0                             |0.5                             |0.0                             |0.0                             |0.5                                   |0.5                                   |0.0                                   |0.0                                   |0.0                                   |1.0                                   |0.0                                   |0.0                                   |0.5                                   |0.0                                   |0.0                                   |0.0                                   |0.0                                   |1.0                                   |0.0                                   |0.0                                   |0.0001          |0.0001        |0.00017690658569335938|2.1457672119140625e-06|0.00026297569274902344|0.0001            |0.0783              |0.8145         |0.0000          |0.0000              |0.0000              |0.0000             |2.1457672119140625e-06|2.1457672119140625e-06|2.1457672119140625e-06|0.0000                |nan                     |0.0000             |0.0000              |0.0000                  |0.0002              |0.0000             |0.00017690658569335938|0.00017690658569335938|0.00017690658569335938|0.0002                |nan                     |0.0000             |0.0002              |0.0000                  |0                  |0                  |0                |0                |not a complete handshake|not a complete handshake|0              |0.1770                    |0.1770                    |0.0877                 |0.0020                 |0.0051                     |0.0715                |0.0840                   |0.0768                     |0.8155                |0.1770                     |0.1770                     |0.0000                         |0.0000                    |0.1770                       |nan                            |0.0000                    |0.0020                    |0.0020                    |0.0020                     |0.0020                     |0.0000                         |0.0000                    |0.0020                       |nan                            |0.0000                    |-50.0                |0.0                  |-18.6667              |-50.0000              |496.8889                  |22.2910              |-6.0000                 |-0.6689                   |-1.1942              |0.0                      |0.0                      |0.0000                    |0.0000                    |0.0000                        |0.0000                   |0.0000                      |nan                           |nan                      |-50.0                    |-50.0                    |-50.0000                  |-50.0000                  |0.0000                        |0.0000                   |-50.0000                    |nan                           |-0.0000                  |0.0                       |0.0                       |0.0000                     |0.0000                     |0.0000                         |0.0000                    |0.0000                       |nan                            |nan                       |0.0                           |0.0                           |0.0000                         |0.0000                         |0.0000                             |0.0000                        |0.0000                           |nan                                |nan                           |0.0                           |0.0                           |0.0000                         |0.0000                         |0.0000                             |0.0000                        |0.0000                           |nan                                |nan                           |-56.0                      |0.0                        |-18.6667                    |0.0000                      |696.8889                        |26.3987                    |0.0000                        |-0.7071                         |-1.4142                    |0.0                            |0.0                            |0.0000                          |0.0000                          |0.0000                              |0.0000                         |0.0000                            |nan                                 |nan                            |-56.0                          |-56.0                          |-56.0000                        |-56.0000                        |0.0000                              |0.0000                         |-56.0000                          |nan                                 |-0.0000                        |0.8884916847830097|2.1963972128035034|2.9004643264490855|0.8193295992246235       |0.901932232285215        |0.022100697044976133              |0.022100697044976133              |0                                |0.022100697044976133                |0.0                              |nan                                   |1.9622641509433962           |0.1333393806079054          |-3.2142857142857135              |2.0                          |2.0                            |6.795179973287486           |2.9591836734693877           |0.09335944726998882         |-1.8221201802349665              |3.0                          |3.0                            |3.154905459468588           |3.9298780487804876            |0.07929760246121922          |-0.6613702393808507               |4.0                           |4.0                             |2.017813313210233            |4.89                          |0.027243118397129208         |1.2175615550562382                |4.875                         |4.875                           |0.5571189856263642           |0.0                           |0                            |nan                               |0.0                           |0.0                             |0                            |1.978395061728395         |0.10197986392552923      |-4.49310788131998             |2.0                       |2.0                         |5.154676429309122        |2.525494907032581         |0.25461002792635956      |-0.051926640798337156         |2.5                       |2.5                         |10.08158944282024        |2.973283924438767          |0.2579070183235096        |-0.13405517342704978           |3.077819531114783          |3.077819531114783            |8.6741469996745           |3.3609061840693277         |0.2017222954642734        |-0.058339779626329226          |3.5026204074720737         |3.5026204074720737           |6.002021015059441         |3.619880201413181          |0.11124651939661229       |-0.13449468249147992           |3.608972760598469          |3.608972760598469            |3.073209973998097         |1.796433744261093          |0.31763280491020696       |-1.3369716825174562            |2.0                        |2.0                          |17.681298067625384        |2.521020401736779          |0.36436548293161          |-1.334882096247833             |2.5                        |2.5                          |14.453095368866972        |3.176249440734047           |0.20999375391115974        |-0.5371152781447651             |3.327819531114783           |3.327819531114783             |6.611374762261403          |3.589902190694938           |0.14497874082905865        |-0.2596325473835012             |3.5275182662886326          |3.5275182662886326            |4.038515066088569          |3.79710869970497            |0.05765523892114071        |0.20856537711751397             |3.7692475629608078          |3.7692475629608078            |1.5183984310383434         |0.5216724435299457   |0.4423148273267106   |0.27309026702768613  |0.1651190969845131   |0.10458081965787844  |0.06142898243793152  |0.035304466419761996 |0.03536981687965755  |0.019995619885046372  |0.04486312197937856   |0.045084221805098634  |0.045307716067189044 |0.045533645205680845  |0.04576205059304602   |0.04599297456153682   |0.04622646043150065   |0.046462552540711     |0.046701296274758004  |0.06121095375090186 |0.061648724668406    |0.06209343417226538  |0.06254525464966174   |0.06300436435888922  |0.06347094768455848   |0.06394519540634402  |0.0644273049821259    |0.06491748084643902   |FREENET|
|172.217.175.3_443_172.24.216.110_52511_TCP_2020-04-16 03:55:24.130404 |2020-04-16 03:55:24.130404|172.217.175.3 |443     |172.24.216.110|52511   |TCP     |0.0003230571746826172 |4            |2                |2                |56                 |56                     |0                      |56               |0                |14.0000           |24.2487          |588.0000              |0.0000              |1.1547                |1.7321           |0.0000            |56                   |0                    |14.0000               |24.2487              |784.0000                  |28.0000                 |0.0000                    |1.0000               |0.0000                |56                   |0                    |14.0000               |24.2487              |0.0000                    |0.0000                  |nan                       |nan                  |0.0000                |80                |20              |20              |20.0000          |0.0000          |20.0000            |nan                  |0.0000          |20.0000          |0.0000               |40                    |20                  |20                  |20.0000              |0.0000              |20.0000                |nan                      |0.0000              |20.0000              |0.0000                   |40                    |20                  |20                  |20.0000              |0.0000              |20.0000                |nan                      |0.0000              |20.0000              |0.0000                   |48.0000              |76                  |20                  |28.0000             |784.0000                 |48.0000                |0.0000                   |0.5833              |20.0000              |20.0000              |20                  |20                  |0.0000              |0.0000                   |20.0000                |nan                      |0.0000              |20.0000              |34.0000          |76              |20              |24.2487         |588.0000             |20.0000            |1.1547               |0.7132          |20.0000          |291               |8191              |0                  |0                  |0          |0         |0            |0              |0         |0          |0              |0                 |0                 |0        |0       |0          |0            |0       |0        |0            |173343.92915129152|173343.92915129152  |0.0               |12381.70922509225  |6190.854612546125  |6190.854612546125  |1.0               |0                     |0                       |0                 |0                     |0                        |0                 |0                   |0                  |0                  |0                     |0                   |0                  |0                  |0                  |2              |1              |0              |0              |0              |4              |0              |0              |1                  |1                  |0                  |0                  |0                  |2                  |0                  |0                  |1                  |0                  |0                  |0                  |0                  |2                  |0                  |0                  |0.5                         |0.25                        |0.0                         |0.0                         |0.0                         |1.0                         |0.0                         |0.0                         |0.25                            |0.25                            |0.0                             |0.0                             |0.0                             |0.5                             |0.0                             |0.0                             |0.25                            |0.0                             |0.0                             |0.0                             |0.0                             |0.5                             |0.0                             |0.0                             |0.5                                   |0.5                                   |0.0                                   |0.0                                   |0.0                                   |1.0                                   |0.0                                   |0.0                                   |0.5                                   |0.0                                   |0.0                                   |0.0                                   |0.0                                   |1.0                                   |0.0                                   |0.0                                   |0.0001          |0.0001        |0.00016498565673828125|3.0994415283203125e-06|0.0003230571746826172 |0.0002            |-0.6974             |0.6878         |0.0000          |0.0000              |0.0000              |0.0000             |3.0994415283203125e-06|3.0994415283203125e-06|3.0994415283203125e-06|0.0000                |nan                     |0.0000             |0.0000              |0.0000                  |0.0002              |0.0000             |0.00016498565673828125|0.00016498565673828125|0.00016498565673828125|0.0002                |nan                     |0.0000             |0.0002              |0.0000                  |0                  |0                  |0                |0                |not a complete handshake|not a complete handshake|0              |0.1650                    |0.1650                    |0.1077                 |0.0030                 |0.0055                     |0.0741                |0.1550                   |-0.6975                    |0.6884                |0.1650                     |0.1650                     |0.0000                         |0.0000                    |0.1650                       |nan                            |0.0000                    |0.0030                    |0.0030                    |0.0030                     |0.0030                     |0.0000                         |0.0000                    |0.0030                       |nan                            |0.0000                    |-50.0                |0.0                  |-18.6667              |-50.0000              |496.8889                  |22.2910              |-6.0000                 |-0.6689                   |-1.1942              |0.0                      |0.0                      |0.0000                    |0.0000                    |0.0000                        |0.0000                   |0.0000                      |nan                           |nan                      |-50.0                    |-50.0                    |-50.0000                  |-50.0000                  |0.0000                        |0.0000                   |-50.0000                    |nan                           |-0.0000                  |0.0                       |0.0                       |0.0000                     |0.0000                     |0.0000                         |0.0000                    |0.0000                       |nan                            |nan                       |0.0                           |0.0                           |0.0000                         |0.0000                         |0.0000                             |0.0000                        |0.0000                           |nan                                |nan                           |0.0                           |0.0                           |0.0000                         |0.0000                         |0.0000                             |0.0000                        |0.0000                           |nan                                |nan                           |-56.0                      |0.0                        |-18.6667                    |0.0000                      |696.8889                        |26.3987                    |0.0000                        |-0.7071                         |-1.4142                    |0.0                            |0.0                            |0.0000                          |0.0000                          |0.0000                              |0.0000                         |0.0000                            |nan                                 |nan                            |-56.0                          |-56.0                          |-56.0000                        |-56.0000                        |0.0000                              |0.0000                         |-56.0000                          |nan                                 |-0.0000                        |0.9308379754926045|2.2815703572712214|3.4854268271702415|0.8229302528329365       |0.8982119852078028       |-0.008773563803899053             |-0.008773563803899053             |0                                |-0.008773563803899053               |-0.0                             |nan                                   |1.9622641509433962           |0.1333393806079054          |-3.214285714285714               |2.0                          |2.0                            |6.795179973287486           |2.9591836734693877           |0.09335944726998882         |-1.8221201802349665              |3.0                          |3.0                            |3.154905459468588           |3.951219512195122             |0.06173309979059935          |-0.44999999999999796              |4.0                           |4.0                             |1.56238092062628             |4.87                          |0.05077524002897475          |-0.3319670359492614               |4.875                         |4.875                           |1.0426127316011242           |0.0                           |0                            |nan                               |0.0                           |0.0                             |0                            |1.9384057971014492        |0.16492531544361985      |-2.2930640912526012           |2.0                       |2.0                         |8.508296647184874        |2.5724778334666065        |0.2712654869206956       |-0.09744363067432067          |2.5                       |2.5                         |10.544910568000697       |3.1021576443179817         |0.2515151505706634        |-0.44604046400593184           |3.2806390622295662         |3.2806390622295662           |8.107748844787022         |3.5733499057674503         |0.20355378694892096       |0.05075660404038486            |3.7181390622295662         |3.7181390622295662           |5.696441499344397         |3.977850420077921          |0.15227125190810567       |0.12371538806530324            |4.151503710565654          |4.151503710565654            |3.8279783256687385        |1.7734979644445792         |0.297691953904718         |-0.9818233226510464            |2.0                        |2.0                          |16.785581933157086        |2.5549838838950896         |0.3391526463285579        |-1.8022831117425704            |2.75                       |2.75                         |13.274159906305064        |3.238379140108662           |0.22744889390841816        |-0.9466036011857416             |3.375                       |3.375                         |7.023541224415935          |3.652681901739047           |0.10861895196044552        |-0.3798860298270178             |3.6761085007312415          |3.6761085007312415            |2.9736767362285748         |3.87787089375906            |0.02740748923911267        |-0.3718896072217968             |3.8203131892755073          |3.8203131892755073            |0.706766418738219          |0.5166191738511514   |0.4079134114732785   |0.26774701501005266  |0.12325422908699872  |0.06131975520139971  |0.03523937809679381  |0.019919806906026127 |0.019957635712556043 |0.019995619885046372  |0.050923450121035475  |0.051215403400888544  |0.051511046788247604 |0.05181045316029581   |0.05211369736213484   |0.0524208562744506    |0.05273200888401322   |0.0530472363571518    |0.053366622116351924  |0.06121095375090186 |0.061648724668406    |0.06209343417226538  |0.06254525464966174   |0.06300436435888922  |0.06347094768455848   |0.06394519540634402  |0.0644273049821259    |0.06491748084643902   |FREENET|
|172.24.216.110_52583_216.58.197.237_443_TCP_2020-04-16 03:55:24.334815|2020-04-16 03:55:24.334815|172.24.216.110|52583   |216.58.197.237|443     |TCP     |75.1824860572815      |15           |8                |7                |3820               |582                    |3238                   |1430             |0                |254.6667          |461.0020         |212522.8889           |0.0000              |1.6510                |1.8102           |0.0000            |1430                 |0                    |254.6667              |461.0020             |28630.6875                |0.0000                  |2.2030                    |2.3259               |0.0000                |1430                 |0                    |254.6667              |461.0020             |341639.6735               |0.0000                  |0.6865                    |1.2636               |0.0000                |336               |32              |20              |22.4000          |4.8000          |20.0000            |1.5000               |0.2143          |20.0000          |23.0400              |172                   |32                  |20                  |21.5000              |3.9686              |20.0000                |2.2678                   |0.1846              |20.0000              |15.7500                  |164                   |32                  |20                  |23.4286              |5.4210              |20.0000                |0.9487                   |0.2314              |20.0000              |29.3878                  |94.2500              |537                 |20                  |168.6066            |28428.1875               |20.5000                |2.2041                   |1.7889              |20.0000              |486.0000             |1450                |20                  |581.8051            |338497.1429              |32.0000                |0.6893                   |1.1971              |20.0000              |277.0667         |1450            |20              |459.6994        |211323.5289          |32.0000            |1.6540               |1.6592          |20.0000          |64240             |60720             |0                  |0                  |0          |0         |0            |0              |0         |0          |0              |0                 |0                 |0        |0       |0          |0            |0       |0        |0            |50.80970582815716 |7.7411646052323215  |43.06854122292484 |0.1995145516812454 |0.09310679078458119|0.1064077608966642 |0.875             |0                     |0                       |0                 |0                     |0                        |0                 |0                   |0                  |0                  |0                     |0                   |0                  |0                  |0                  |2              |4              |0              |1              |2              |14             |1              |0              |1                  |2                  |0                  |1                  |1                  |7                  |1                  |0                  |1                  |2                  |0                  |0                  |1                  |7                  |0                  |0                  |0.13333333333333333         |0.26666666666666666         |0.0                         |0.06666666666666667         |0.13333333333333333         |0.9333333333333333          |0.06666666666666667         |0.0                         |0.06666666666666667             |0.13333333333333333             |0.0                             |0.06666666666666667             |0.06666666666666667             |0.4666666666666667              |0.06666666666666667             |0.0                             |0.06666666666666667             |0.13333333333333333             |0.0                             |0.0                             |0.06666666666666667             |0.4666666666666667              |0.0                             |0.0                             |0.125                                 |0.25                                  |0.0                                   |0.125                                 |0.125                                 |0.875                                 |0.125                                 |0.0                                   |0.14285714285714285                   |0.2857142857142857                    |0.0                                   |0.0                                   |0.14285714285714285                   |1.0                                   |0.0                                   |0.0                                   |5.3702          |13.4297       |44.999948024749756    |2.86102294921875e-06  |75.1824860572815      |0.0014            |2.2249              |2.5008         |0.0000          |180.3571            |10.7402             |17.4084            |44.999948024749756    |0.00028896331787109375|75.18116688728333     |0.0386                |1.1176                  |1.6209             |0.0003              |303.0509                |12.5302             |18.2139            |45.040865898132324    |2.86102294921875e-06  |75.18103003501892     |0.0375                |0.8804                  |1.4536             |0.0000              |331.7456                |4.0                |3.5                |291.0            |291.0            |0.0003                  |0.0016                  |3              |0.0030                    |63.6400                   |84.4633                |0.0030                 |64868.2551                 |254.6925              |1.3875                   |3.2931                     |3.0154                |30.1717                    |0.0030                     |511.2323                       |22.6104                   |37.4605                      |-0.1628                        |0.7494                    |0.2890                    |999.9480                  |168.7381                   |0.2890                     |115587.7827                    |339.9820                  |38.6180                      |2.0250                         |2.0148                    |-1228.0              |1424.0               |-0.4286               |-12.0000              |336583.5306               |580.1582             |0.5000                  |0.3588                    |-1353.7025           |-648.0                   |1424.0                   |-1.0000                   |-6.0000                   |468529.0000                   |684.4918                 |-104.0000                   |1.2641                        |-684.4918                |-517.0                   |517.0                    |-1.7143                   |-517.0000                 |77556.4898                    |278.4897                 |-1.0000                     |0.0185                        |-162.4523                |-12.0                     |12.0                      |-0.8571                    |0.0000                     |30.1224                        |5.4884                    |0.0000                       |-0.2743                        |-6.4031                   |-12.0                         |12.0                          |-2.0000                        |0.0000                         |68.0000                            |8.2462                        |0.0000                           |0.2283                             |-4.1231                       |-12.0                         |0.0                           |-1.7143                        |0.0000                         |17.6327                            |4.1991                        |0.0000                           |-2.0412                            |-2.4495                       |-1228.0                    |1430.0                     |0.0000                      |0.0000                      |338215.7143                     |581.5632                   |0.0000                        |0.3656                          |inf                        |-648.0                         |1430.0                         |0.0000                          |0.0000                          |473668.0000                         |688.2354                       |-101.0000                         |1.2519                              |inf                            |-517.0                         |517.0                          |0.0000                          |-517.0000                       |77538.8571                          |278.4580                       |0.0000                            |0.0000                              |inf                            |0.8783769840188993|2.1357171535405666|2.8172078815692396|0.7887942564511822       |0.8510953707802572       |0.021800900913703194              |0.02180090091370242               |0.0                              |0.02180090091370242                 |0.0                              |nan                                   |1.8539820858942189           |0.463605105291331           |-3.4227566657276176              |2.0                          |2.0                            |25.005910726894832          |2.76288807104166             |0.6850796674001831          |-3.4095076815486727              |3.0                          |3.0                            |24.795780711518127          |3.6629638970142433            |0.898269609896064            |-3.4449941454564477               |4.0                           |4.0                             |24.52302657496193            |4.535224826913129             |1.0974066111299081           |-3.4605927210701752               |4.9375                        |4.9375                          |24.19740262087185            |5.353529159930025             |1.2628951803068227           |-3.441157302683983                |5.84375                       |5.84375                         |23.589956131355596           |1.9188091977207955        |0.19044449642934055      |-2.1285361376385867           |2.0                       |2.0                         |9.925139855257875        |2.4249200444296832        |0.3527025894466915       |-1.0859205157503056           |2.5                       |2.5                         |14.544916244017585       |2.8436047790264056         |0.46636274346394324       |-1.5764666148888244            |2.875                      |2.875                        |16.400406515831527        |3.190866371410148          |0.5499999682245922        |-1.9946007323374513            |1.5                        |1.5                          |17.236697003438888        |3.457211122013448          |0.60568465459567          |-2.2926131883665044            |1.5                        |1.5                          |17.519458118685122        |1.6853946092879553         |0.5064297281916712        |-2.1100625928021377            |2.0                        |2.0                          |30.04813978879566         |2.3987795359722295         |0.6673222423182482        |-2.5006622645100993            |2.75                       |2.75                         |27.819240255765372        |2.9627720495994145          |0.7821260351120574         |-2.8899919688678164             |3.327819531114783           |3.327819531114783             |26.398454623527506         |3.3418594668374775          |0.8438049983810758         |-3.203940207714028              |0.0                         |0.0                           |25.249565601260876         |3.5491789901223476          |0.8592168423304838         |-3.449378753223562              |0.0                         |0.0                           |24.208890132668817         |0.5252742994358254   |0.46497097436108986  |0.24324066051212784  |0.147150080217106    |0.08517061391559065  |0.05087824414069895  |0.029444302424966557 |0.014115907090665522 |0.008964983174998161  |0.0011766421835640722 |0.0011767338797915839 |0.0011768255910658229|0.0011769173173905622 |0.0011770090587695755 |0.0011771008152066378 |0.0011771925867055258 |0.0011772843732700171 |0.0011773761749038904 |0.02878591117910892 |0.005707766014465836 |0.0031160901684905624|0.003116448765689874  |0.0016893794946541208|0.0016895760376232068 |0.0016897726288473062|0.0016899692683445377 |0.001690165956133029  |FREENET|
|172.24.216.110_52527_172.217.175.74_443_TCP_2020-04-16 03:55:52.462962|2020-04-16 03:55:52.462962|172.24.216.110|52527   |172.217.175.74|443     |TCP     |104.46239304542542    |10           |5                |5                |59                 |3                      |56                     |56               |0                |5.9000            |16.7060          |279.0900              |0.0000              |2.6631                |2.8315           |0.0000            |56                   |0                    |5.9000                |16.7060              |0.2400                    |1.0000                  |-0.4082                   |0.8165               |1.0000                |56                   |0                    |5.9000                |16.7060              |501.7600                  |0.0000                  |1.5000                    |2.0000               |0.0000                |236               |32              |20              |23.6000          |5.4991          |20.0000            |0.8729               |0.2330          |20.0000          |30.2400              |100                   |20                  |20                  |20.0000              |0.0000              |20.0000                |nan                      |0.0000              |20.0000              |0.0000                   |136                   |32                  |20                  |27.2000              |5.8788              |32.0000                |-0.4082                  |0.2161              |32.0000              |34.5600                  |20.6000              |21                  |20                  |0.4899              |0.2400                   |21.0000                |-0.4082                  |0.0238              |21.0000              |38.4000              |76                  |20                  |19.3659             |375.0400                 |32.0000                |1.2706                   |0.5043              |32.0000              |29.5000          |76              |20              |16.3355         |266.8500             |21.0000            |2.2063               |0.5537          |20.0000          |8193              |250               |0                  |0                  |0          |0         |0            |0              |0         |0          |0              |0                 |0                 |0        |0       |0          |0            |0       |0        |0            |0.5647965576888889|0.028718469035028248|0.5360780886538606|0.09572823011676082|0.04786411505838041|0.04786411505838041|1.0               |0                     |0                       |0                 |0                     |0                        |0                 |0                   |0                  |0                  |0                     |0                   |0                  |0                  |0                  |2              |1              |0              |0              |0              |10             |0              |0              |1                  |0                  |0                  |0                  |0                  |5                  |0                  |0                  |1                  |1                  |0                  |0                  |0                  |5                  |0                  |0                  |0.2                         |0.1                         |0.0                         |0.0                         |0.0                         |1.0                         |0.0                         |0.0                         |0.1                             |0.0                             |0.0                             |0.0                             |0.0                             |0.5                             |0.0                             |0.0                             |0.1                             |0.1                             |0.0                             |0.0                             |0.0                             |0.5                             |0.0                             |0.0                             |0.2                                   |0.0                                   |0.0                                   |0.0                                   |0.0                                   |1.0                                   |0.0                                   |0.0                                   |0.2                                   |0.2                                   |0.0                                   |0.0                                   |0.0                                   |1.0                                   |0.0                                   |0.0                                   |11.6069         |18.4017       |45.01612591743469     |2.288818359375e-05    |104.46239304542542    |0.0010            |1.1621              |1.5854         |0.0000          |338.6213            |26.1156             |19.5716            |45.0170578956604      |0.0007369518280029297 |104.46239304542542    |29.7223               |-0.1971                 |0.7494             |0.0007              |383.0462                |26.1152             |19.5720            |45.01711702346802     |5.507469177246094e-05 |104.46065402030945    |29.7217               |-0.1971                 |0.7494             |0.0001              |383.0615                |1.6666666666666667 |1.6666666666666667 |1.0              |1.0              |not a complete handshake|not a complete handshake|0              |0.0550                    |441.8790                  |51.3770                |0.0230                 |19084.9488                 |138.1483              |0.9320                   |2.4691                     |2.6889                |115.1635                   |0.0550                     |35625.5220                     |188.7472                  |9.3600                       |1.1504                         |1.6390                    |0.7370                    |442.9480                  |115.5982                   |0.7370                     |35761.3375                     |189.1067                  |9.3540                       |1.1507                         |1.6359                    |-50.0                |44.0                 |-0.1111               |11.0000               |564.0988                  |23.7508              |0.0000                  |-0.3069                   |-213.7569            |-50.0                    |44.0                     |-1.5000                   |0.0000                    |1106.7500                     |33.2679                  |0.0000                      |-0.1350                       |-22.1786                 |-1.0                     |0.0                      |-0.2500                   |0.0000                    |0.1875                        |0.4330                   |0.0000                      |-1.1547                       |-1.7321                  |-12.0                     |12.0                      |0.0000                     |-12.0000                   |96.0000                        |9.7980                    |0.0000                       |0.0000                         |inf                       |-12.0                         |0.0                           |-3.0000                        |0.0000                         |27.0000                            |5.1962                        |0.0000                           |-1.1547                            |-1.7321                       |0.0                           |0.0                           |0.0000                         |0.0000                         |0.0000                             |0.0000                        |0.0000                           |nan                                |nan                           |-56.0                      |56.0                       |-0.1111                     |-1.0000                     |697.4321                        |26.4089                    |0.0000                        |0.0126                          |-237.6805                  |-56.0                          |56.0                           |0.0000                          |0.0000                          |1568.0000                           |39.5980                        |0.0000                            |0.0000                              |inf                            |-1.0                           |0.0                            |-0.2500                         |0.0000                          |0.1875                              |0.4330                         |0.0000                            |-1.1547                             |-1.7321                        |0.9226411172937602|2.158147833665959 |2.7951802081115016|0.803347527181771        |0.8997131598287303       |0.02130231356377793               |0.02130231356377793               |0                                |0.02130231356377793                 |0.0                              |nan                                   |1.9341299665081988           |0.2097653868624564          |-3.5987058595777386              |2.0                          |2.0                            |10.84546491160356           |2.9164545973505684           |0.22578811902920523         |-3.625035944058266               |3.0                          |3.0                            |7.741869845473362           |3.899495898434427             |0.14730795069586897          |-2.701807761934496                |3.875                         |3.875                           |3.7776152234192706           |4.88978249162705              |0.08319498948439431          |-2.0603626204706176               |4.9375                        |4.9375                          |1.7014047072002096           |0.0                           |0                            |nan                               |0.0                           |0.0                             |0                            |1.9166666666666667        |0.18685877318798397      |-1.788854381999833            |2.0                       |2.0                         |9.749153383720904        |2.438704714116621         |0.31171488465236125      |-0.9265749404690449           |2.5                       |2.5                         |12.781985569961659       |2.8737969379790713         |0.29603134612566445       |-0.9779093661708974            |3.077819531114783          |3.077819531114783            |10.301053015034576        |3.2300020571130674         |0.2249231507479697        |-1.2207834420395711            |3.3731919871571896         |3.3731919871571896           |6.963560603704476         |3.5208171563567894         |0.09944719078010097       |-0.015619091318652476          |3.536238041347632          |3.536238041347632            |2.824548573917006         |1.6934357608507526         |0.43522882695021564       |-1.8616512206133413            |2.0                        |2.0                          |25.700935164588955        |2.4939903367108145         |0.42518233935580596       |-1.6384339404381985            |2.75                       |2.75                         |17.048275331994887        |3.123375881910334           |0.3150934739437112         |-3.0260668004690903             |3.327819531114783           |3.327819531114783             |10.088234200969504         |3.549441075793386           |0.14836374104099984        |-1.405788619944063              |3.6792292966721747          |3.6792292966721747            |4.179918411741402          |3.7984929537397316          |0.0632246165319853         |-1.7958546853985817             |3.8063038618967613          |3.8063038618967613            |1.6644658105720256         |0.5189089456712882   |0.44834401808555224  |0.3554642939690094   |0.2894310258468265   |0.24897138028454088  |0.22641255122744397  |0.21454424483566184  |0.20210977374854538  |0.18905372899895542   |0.041251618902190645  |0.04143561263581881   |0.04162140609072042  |0.041809026688627134  |0.04199850242115954   |0.042189861864875694  |0.04238313419680283   |0.04257834921047045   |0.042775537332463955  |0.21976421635191018 |0.16751658603888178  |0.13723115348408396  |0.10233140375727616   |0.06035556603907246  |0.06077995466122861   |0.06121095375090186  |0.061648724668406     |0.06209343417226538   |FREENET|
|172.24.216.110_52588_216.58.197.202_443_TCP_2020-04-16 03:55:25.552091|2020-04-16 03:55:25.552091|172.24.216.110|52588   |216.58.197.202|443     |TCP     |240.0520520210266     |34           |17               |17               |2600               |1203                   |1397                   |601              |0                |76.4706           |160.7933         |25854.4844            |1.0000              |2.3315                |2.1027           |0.0000            |601                  |0                    |76.4706               |160.7933             |25221.1211                |1.0000                  |2.5294                    |2.2442               |0.0000                |601                  |0                    |76.4706               |160.7933             |26422.7336                |0.0000                  |2.1499                    |1.9781               |0.0000                |764               |32              |20              |22.4706          |4.8521          |20.0000            |1.4548               |0.2159          |20.0000          |23.5433              |352                   |32                  |20                  |20.7059              |2.8235              |20.0000                |3.7500                   |0.1364              |20.0000              |7.9723                   |412                   |32                  |20                  |24.2353              |5.7346              |20.0000                |0.6155                   |0.2366              |20.0000              |32.8858                  |91.4706              |621                 |20                  |158.5219            |25129.1903               |21.0000                |2.5321                   |1.7330              |20.0000              |106.4118             |600                 |20                  |160.4978            |25759.5363               |32.0000                |2.1721                   |1.5083              |32.0000              |98.9412          |621             |20              |159.6877        |25500.1730           |32.0000            |2.3429               |1.6140          |20.0000          |64240             |60720             |0                  |0                  |0          |0         |0            |0              |0         |0          |0              |0                 |0                 |0        |0       |0          |0            |0       |0        |0            |10.83098427241214 |5.011413107581463   |5.819571164830677 |0.1416359481776972 |0.0708179740888486 |0.0708179740888486 |1.0               |0                     |0                       |0                 |549.0                 |4.0                      |14679.890194378391|0                   |0                  |0                  |0                     |1                   |549                |4                  |0.03739809989929199|2              |13             |0              |1              |2              |33             |1              |0              |1                  |6                  |0                  |1                  |1                  |16                 |1                  |0                  |1                  |7                  |0                  |0                  |1                  |17                 |0                  |0                  |0.058823529411764705        |0.38235294117647056         |0.0                         |0.029411764705882353        |0.058823529411764705        |0.9705882352941176          |0.029411764705882353        |0.0                         |0.029411764705882353            |0.17647058823529413             |0.0                             |0.029411764705882353            |0.029411764705882353            |0.47058823529411764             |0.029411764705882353            |0.0                             |0.029411764705882353            |0.20588235294117646             |0.0                             |0.0                             |0.029411764705882353            |0.5                             |0.0                             |0.0                             |0.058823529411764705                  |0.35294117647058826                   |0.0                                   |0.058823529411764705                  |0.058823529411764705                  |0.9411764705882353                    |0.058823529411764705                  |0.0                                   |0.058823529411764705                  |0.4117647058823529                    |0.0                                   |0.0                                   |0.058823529411764705                  |1.0                                   |0.0                                   |0.0                                   |7.2743          |16.1490       |45.041362047195435    |1.9073486328125e-06   |240.0520520210266     |0.0012            |1.8616              |2.2200         |0.0000          |260.7891            |15.0033             |20.5423            |45.04812216758728     |9.202957153320312e-05 |240.0520520210266     |0.0055                |0.7309                  |1.3692             |0.0001              |421.9868                |15.0031             |20.5416            |45.04262089729309     |1.9073486328125e-06   |240.05037999153137    |0.0089                |0.7309                  |1.3692             |0.0000              |421.9564                |2.8333333333333335 |2.8333333333333335 |200.5            |200.5            |0.0003                  |0.0015                  |3              |0.0020                    |942.1520                  |31.8804                |1.2330                 |25967.2952                 |161.1437              |0.7210                   |5.4558                     |5.0546                |65.6488                    |0.0020                     |51353.9372                     |226.6141                  |1.9630                       |3.5986                         |3.4519                    |0.0920                    |943.5260                  |65.7532                    |0.0920                     |51556.7174                     |227.0610                  |1.7335                       |3.5923                         |3.4532                    |-595.0               |601.0                |-0.3636               |11.0000               |47256.2314                |217.3850             |0.0000                  |-0.3654                   |-597.8087            |-549.0                   |410.0                    |-0.3750                   |0.0000                    |48672.8594                    |220.6193                 |0.0000                      |-0.4725                       |-588.3180                |-537.0                   |601.0                    |-0.7500                   |0.0000                    |52991.0625                    |230.1979                 |0.0000                      |0.2385                        |-306.9305                |-12.0                     |12.0                      |-0.3636                    |0.0000                     |47.8678                        |6.9187                    |0.0000                       |-0.0003                        |-19.0263                  |-12.0                         |12.0                          |-0.7500                        |0.0000                         |26.4375                            |5.1417                        |0.0000                           |-0.3538                            |-6.8557                       |-12.0                         |0.0                           |-0.7500                        |0.0000                         |8.4375                             |2.9047                        |0.0000                           |-3.6148                            |-3.8730                       |-601.0                     |601.0                      |0.0000                      |-1.0000                     |47740.0000                      |218.4949                   |0.0000                        |-0.3723                         |inf                        |-549.0                         |416.0                          |0.0000                          |0.0000                          |49297.7500                          |222.0310                       |0.0000                            |-0.4465                             |inf                            |-537.0                         |601.0                          |0.0000                          |0.0000                          |52982.6250                          |230.1795                       |0.0000                            |0.2288                              |inf                            |0.8942445706417707|2.150953020583429 |3.086908065223165 |0.8227516518295471       |0.8925632860869824       |0.029582749112714076              |0.02958274911271368               |0.0                              |0.02958274911271368                 |0.0                              |nan                                   |1.9304090019665578           |0.2201378792234475          |-4.087075389153885               |2.0                          |2.0                            |11.403691083039257          |2.877550577066711            |0.30187042543490095         |-3.2612399556016367              |3.0                          |3.0                            |10.490534131379842          |3.8146799238451052            |0.3645385584122876           |-2.8526334097729693               |4.0                           |4.0                             |9.556203028558201            |4.7284154773006675            |0.40729305095257273          |-2.758683430174989                |4.875                         |4.875                           |8.613732293784937            |5.583567272996594             |0.43345243344264694          |-2.78147155166476                 |5.78125                       |5.78125                         |7.763001899142899            |1.942242093875882         |0.16531664153178116      |-2.7695773969455693           |2.0                       |2.0                         |8.511639308665178        |2.473484180051568         |0.27696191376106444      |-0.5332832493664541           |2.5                       |2.5                         |11.19723813051799        |2.9162460631032947         |0.3356460614854784        |-0.8940224634284984            |3.077819531114783          |3.077819531114783            |11.509524718511027        |3.285590543462844          |0.35349669513860144       |-1.3421460869150579            |3.4356919871571896         |3.4356919871571896           |10.759000260757814        |3.57609004965907           |0.32877730398057614       |-1.6783073412241207            |3.7112462375228104         |3.7112462375228104           |9.193764681958175         |1.748870152230277          |0.36353278328510547       |-1.721330981877461             |2.0                        |2.0                          |20.786722377387708        |2.487351925312736          |0.4259625513201469        |-1.8470344301132278            |2.75                       |2.75                         |17.125142083245436        |3.0817297244046573          |0.44562445366737435        |-2.168269793267962              |3.327819531114783           |3.327819531114783             |14.460205583196045         |3.487825841860779           |0.40249588230075084        |-2.506039087766117              |3.6556390622295662          |3.6556390622295662            |11.540022367803106         |3.718584257167211           |0.3295012767435902         |-3.054272880723877              |3.930036532577266           |3.930036532577266             |8.86093346166645           |0.5219630694477965   |0.4487024227880742   |0.2605225595414136   |0.1646934568972061   |0.09703052482109381  |0.0590531614714257   |0.030229203608302977 |0.015136276193994963 |0.008386106858975787  |0.001690559476656346  |0.0016907563094274722 |0.0016909531905624589|0.00169115012007948   |0.0016913470979967179 |0.0016915441243323638 |0.001691741199104619  |0.0016919383223316935 |0.0016921354940318068 |0.026997777491195765|0.0043646559901778376|0.004365389010455225 |0.0043661222923202    |0.0023759206994786474|0.00237632466281833   |0.002376728771439976 |0.002377133025423563  |0.0023775374248491293 |FREENET|

----

# Copyright (c) 2023

For citation in your works and also understanding NTLFlowLyzer completely, you can find below published papers:

- “Toward Generating a New Cloud-based Distributed Denial of Service (DDoS) Dataset and Intrusion Traffic Characterization”, MohammadMoein Shafi, Arash Habibi Lashkari, Vicente Rodriguez, and Ron Nevo, Information, Vol 15(3), 131, (2024)
- "Adit Sharma, Arash Habibi Lashkari. "XAI-Driven Encrypted Traffic Detection and Characterization to Enhance Information Security." International Journal of Information Security, 2025. 
"Sharma, A., Habibi Lashkari, A. Hybrid attention-enhanced explainable model for encrypted traffic detection and classification. Int. J. Inf. Secur. 24, 144 (2025). https://doi.org/10.1007/s10207-025-01064-6"

# Contributing

Any contribution is welcome in form of pull requests.


# Project Team members 

* [**Arash Habibi Lashkari:**](http://ahlashkari.com/index.asp) Founder and supervisor

* [**Moein Shafi:**](https://github.com/moein-shafi) Graduate student, Researcher and developer - York University ( 2 years, 2022 - 2024)

* [**Sepideh Niktabe:**](https://github.com/sepideh2020) Graduate students, Researcher and developer - York University (6 months, 2022-2023)

* [**Mehrsa Khoshpasand:**](https://github.com/Khoshpasand-mehrsa) Researcher Assistant (RA) - York University (3 months, 2022)

* [**Parisa Ghanad:**](https://github.com/parishisit) Volunteer Researcher and developer - Amirkabir University (4 months, 2022)

* [**Adit Sharma**](https://github.com/aditsharma3)  Graduate student, Researcher and developer - York University ( 2 years, 2023 - 2025)

# Acknowledgment

This project has been made possible through funding from the Natural Sciences and Engineering Research Council of Canada — NSERC (#RGPIN-2020-04701) and Canada Research Chair (Tier II) - (#CRC-2021-00340) to Arash Habibi Lashkari.
