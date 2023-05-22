# Blink: 

This is the repository of code that we have used to simulate a Blink based sytem.

`python_code` contains the Python-based implementation of Blink, used to run the CAIDA pcaps.<br/>
`controller` contains the controller code of Blink, written in Python.<br/>
`util` contains few helper files  

#Getting Started :

1. Ensure that the python version being used to run the files is version 2.7.18 and the dependencies( with versions) mentioned in requirements.txt are downloaded before going ahead with the next steps.
2. Installation :
* Download the Blink-Master directory as the files required are located in it.
* Download the pcaps to be run on Blink implementation.
3.First, build the python module for the murmur hash functions originally written in C:

```
cd murmur
python setup.py build_ext --inplace
```
4. Now build the required log directories, with `mkdir` 
* Go to the Blink-Master folder and create the main log directory with `mkdir log`.
* Go to the created log directory and create the logs directories for retransmissions, flowselector, pipeline,   
    * `mkdir instance-logs`
    * `mkdir pipeline-logs`
    * `mkdir flowselector-logs`
    * `mkdir slidingwindow-logs`
    * `mkdir retransmission-logs`
5.Then you can start the controller version of the python implementation with:

```
python -m python_code.controller.controller -p 10000 --prefixes_file python_code/pcap/prefixes_file.txt
```
* The argument --prefixes_file indicates a file in which there is a list of prefixes that Blink should monitor. We included one pcap file as an example in the directory python_code/pcap. If you just want to consider all the traffic, regardless of their actual destination IP, you can just use 0.0.0.0//0.
6. Then you need to run the Blink pipeline:

```
python -m python_code.blink.main -p 10000 --pcap <path to pcap file>
```
7. Once you get the code working you can look into various aspects of the code to modify the parameters of the set up such as blink monitoring window, flow stats manitoring window ( in p4pipeline.py file in python_code) etc.

#Understanding the Output: 

Should mention more about the generated logs ??

