# IoT Network Analyzer

This tool is a prototype which is developed during the research paper 'IoT network traffic analysis: opportunities and challenges for forensic investigators?'. The tool provides further forensic components to analyze recorded network trafic (*.pcap files) which enables the user to investigate the behaviour of IOT-devices.

## Authors of the Research Paper

* <b>Tina Wu</b> - University of Oxford (Corresponding author)<sup><a id="anker1" title="Department of Computer Science University of Oxford Parks Road, Oxford, UK" href="#fn1">[1]</a></sup>
* [Frank Breitlinger](http://www.FBreitinger.de/) - University of Liechtenstein<sup><a id="anker2" title="Hilti Chair for Data and Application Security Institute of Information Systems University of Liechtenstein, Fürst-Franz-Josef-Strasse, 9490 Vaduz, Liechtenstein" href="#fn1">[2]</a></sup> 
* <b>Stephen Niemann</b> - University of Liechtenstein<sup><a id="anker2" title="Hilti Chair for Data and Application Security Institute of Information Systems University of Liechtenstein, Fürst-Franz-Josef-Strasse, 9490 Vaduz, Liechtenstein" href="#fn1">[2]</a></sup> 

### Introduction
Although our results can be found using separate open source tools,  it  would  require  an  investigator  considerable  amount
of  time  to  manually  extract  the  data. This is the reason why we built this tool to automate the steps in order to make the anylzation process more effective. The IoT Network Analyzer takes a PCAP file as an input to allow further investigation.

The following features are currently implemented:
* creation of a port whitelist based on provided input
* overview of used ports and their call amounts
* overview of all established connections (origin with their destinations)
* overview of all active IP adresses within the researched PCAP file
* overview of all geolocation of IP adresses within the PCAP which are not in a private network or are part of known multicast address spaces
* overview of sent cleartext with the corresponding origin and destination IP adresses
* overview of IP adresses with their destination adresses and the average entropy

### Usage
The tool has an integrated command line support based on cmd2.
To get started with the tool on the CLI the user needs first to launch the actual file after installing the necessary requirements.
The tool has currently two major commands:
```python
load -f *FILENAME*
```
load takes a filename as an argument which will be used to import the given file. It will directly start to analyze the given data.

```
analyze
```
analyze is then the fundamental command to start investigating the actual file. Analyze has several attributes:

**Overview of all used Ports and call amounts:**
```python 
analyze -po
```

**Overview of all established connections:**
```python
analyze -cn
```

**Overview of all recoreded IPs (origin & destination):**
```python
analyze -ips
```

**all IPs and their geolocation informations:**
```python
analyze -g
```

**Overview of IPs their send utf-8 cleartext and the destination IP:**
``` python
analyze -ct
```

**Overview of IPs their destination and the average entropy:**
``` python
analyze -e
```

**Overview of the analyzed packets:**
``` python
analyze -pa
```

**Output of data**
all the generated data can be easily send to external files by using pipe commands like '>', '<', '|' the following is an example which would extract the Overview of the analyzed packets to a files named 'test.txt'
``` python
analyze -pa > test.txt
```
They same approach can be adapted to all other commands. Further informations can be found here: https://cmd2.readthedocs.io/en/latest/features/redirection.html#output-redirection-and-pipes

### Outlook
The tool will be further developed during the research project, based on occuring demand of features. Next steps are to improve the functionalities of the CLI like finding all entries for a specific IP.
