RoutscoutROUTESCOUT is a closed-loop control system that dynamically adapts how a stub AS forwardsits outgoing traffic across multiple policy-compliant routes according to observed performance and the operator’s objectives. By evaluating average delays and losses of all routes at regularintervals, ROUTSCOUT makes splitting decisions according to the operator’s objectives. Thiscode mimics the ROUTSCOUT implementation for a pcap.

Getting Started
1.Dependencies
The following Python libraries should be installed to run the code:scapy, mmh3 (hash) and ipaddr
2.Installation and Execution
-Download the following .py files:  DelayMonitor.py,  LossMonitor.py,  pcap_parser.py,and main.py.
-Download the pcaps to be run on Routscout implementation.
-In main.py code, replace the input with pcap you want to test implementation on. Makesure that all the files are in a single folder.
-To  run  on  the  terminal,  go  to  the  file  directory  where  the  files  are  downloaded  and execute the following command: "python3 main.py" 

Output interpretation
The output displays two lists:
1. The first one is the list of average delays collected at every second.
2. 2. The second one is the list of percentage changes in average delays between consecutive intervals.Note that the time interval for collecting delays can be altered as required.
