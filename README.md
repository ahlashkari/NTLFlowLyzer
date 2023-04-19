# NetFlowMeter
As part of the Universal User Profiling (UUP), NetFlowMeter is a Python open-source project to extract network layer features from a TCP-based network traffic for Anomaly Profiling (AP).  

NetFlowMeter is generating bidirectional flows from a TCP-based network traffic, where the first packet determines the forward (source to destination) and backward (destination to source) directions, hence the statistical time-related features can be calculated separately in the forward and backward directions. Additional functionalities include, selecting features from the list of existing features, adding new features, and controlling the duration of flow timeout.

NOTE: TCP flows are usually terminated upon connection teardown (by FIN packet) or a flow timeout value that can be assigned arbitrarily in the source code (by default is it 600 seconds).

For citation in your works and also understanding NetFlowMEter completely, you can find below published papers:

????????????????????????????????????????????????????????????


# Project Team members 

* [**Arash Habibi Lashkari:**](http://ahlashkari.com/index.asp) Founder and supervisor

* [**Moein Shafi:**](https://github.com/moein-shafi) Graduate student, Researcher and developer - York University 

* [**Sepideh Niktabe:**](https://github.com/sepideh2020) Graduate students, Researcher and developer - York University (6 months, 2022-2023)

* [**Mehrsa Khoshpasand:**](https://github.com/Khoshpasand-mehrsa) Researcher Assistant (RA) - York University (3 months, 2022)

* [**Parisa Ghanad:**](https://github.com/parishisit) Volunteer Researcher and developer - Amirkabir University (4 months, 2022)


# Acknowledgement
This project has been made possible through funding from the Natural Sciences and Engineering Research Council of Canada — NSERC (#RGPIN-2020-04701) and Canada Research Chair (Tier II) - (#CRC-2021-00340) to Arash Habibi Lashkari.


