#!/bin/bash

# Set the end value for the loop
END=500

# Set the path to the attack pcap file
attack_pcap="path/to/attack.pcap.gz"

# Set the output directory for attack flows
output_directory="path/to/output/directory/"

# Initialize counters
c=0
temp=0

# Loop through the range of stream numbers
for ((i=100; i<=END; i++)); do
    # Extract packets from the attack pcap file for the specified stream
    tshark -nr "$attack_pcap" -c 1 -2 -R "tcp.stream==$i && tcp.len>0" -w "$output_directory/$i.pcap"
    
    # Count the number of packets captured
    c=$(tshark -r "$output_directory/$i.pcap" | wc -l)
    
    # Check if the number of packets captured is the same as the previous iteration
    if (($c == $temp)); then
        # Remove the pcap file if the packet count is the same
        rm "$output_directory/$i.pcap"
    fi
    
    # Update the temporary count for the next iteration
    temp=$c
done
