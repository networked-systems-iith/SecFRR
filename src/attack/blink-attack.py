from scapy.all import *
from scapy.utils import rdpcap
import os
import time
import numpy as np

# Path to directory containing attack PCAP files
path = "attack_new/"

# Counter to start 10 flows each second
counter = 4

# Initialize counter variable for time increment
c = 0

# Loop for each second
for j in np.arange(0, 60, 1):
    i = 0
    
    # Loop through each file in the directory
    for name in os.listdir(path):
        if 'readme' in name:
            continue
        
        # Read PCAP file
        pkts = rdpcap("attack_new/" + name)  

        # Adjust timestamps and append packets to result PCAP file
        for pkt in pkts:
            pkt.time = j + c
            c += 0.001
            wrpcap("attack_each_sec_newflow_new.pcap", pkt, append=True)

        # Check if counter reached to start 10 flows
        if (i + 1 == counter): 
            counter += 4  # Each second start 10 flows 
            c = 0
            break
        else:
            i += 1
