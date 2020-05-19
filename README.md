# IoT Network Analyzer

This tool is a prototype which is developed during the research paper 'IoT network traffic analysis: opportunities and challenges for forensic investigators?'

## Authors of the Research Paper

* <b>Tina Wu</b> - University of Oxford (Corresponding author)<sup><a id="anker1" title="Department of Computer Science University of Oxford Parks Road, Oxford, UK" href="#fn1">[1]</a></sup>
* [Frank Breitlinger](http://www.FBreitinger.deg/) - University of Liechtenstein<sup><a id="anker2" title="Hilti Chair for Data and Application Security Institute of Information Systems University of Liechtenstein, Fürst-Franz-Josef-Strasse, 9490 Vaduz, Liechtenstein" href="#fn1">[2]</a></sup> 
* <b>Stephen Niemann</b> - University of Liechtenstein<sup><a id="anker2" title="Hilti Chair for Data and Application Security Institute of Information Systems University of Liechtenstein, Fürst-Franz-Josef-Strasse, 9490 Vaduz, Liechtenstein" href="#fn1">[2]</a></sup> 

### Introduction
Although our results can be found using separate open source tools,  it  would  require  an  investigator  considerable  amount
of  time  to  manually  extract  the  data. This is the reason why built this tool to automate the steps in order to make the anylzation process more effective. The IoT Network Analyzer takes a PCAP file as an input to allow further investigation.

The following features are currently implemented:
* creation of a port whitelist based on provided input
* overview of used ports and their call amounts
* overview of all established connections (origin with their destinations)
* overview of all active IP adresses within the researched PCAP file
* overview of all geolocation of IP adresses within the PCAP which are not in a private network or are part of known multicast address spaces
* overview of sent cleartext with the corresponding origin and destination IP adresses
* overview of IP adresses with their destination adresses and the average entropy

### Outlook
The tool will be further developed during the research project, based on occuring demand of features. Next steps are to implement a CLI.
