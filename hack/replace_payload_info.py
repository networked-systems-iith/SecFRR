from scapy.all import *
import os
from pathlib import Path

# Set the input and output directory paths
input_directory_path = "/path/to/input/directory/"
output_directory_path = "/path/to/output/directory/"

# Get a list of all files in the input directory
files = os.listdir(input_directory_path)

# Loop through each file in the input directory
for file in files:
    print("Processing file:", file)
    # Read the packets from the input PCAP file
    pkts = rdpcap(input_directory_path + file)
    
    # Extract the file name and extension
    file_name, file_extension = os.path.splitext(file)
    
    # Loop through each packet in the PCAP file
    for pkt in pkts:
        # Check if the packet is of TCP protocol
        if IP in pkt and TCP in pkt:
            # Create a new packet with modified TCP layer
            new_pkt = (Ether() / IP(version=pkt[IP].version, ihl=pkt[IP].ihl, tos=pkt[IP].tos, len=pkt[IP].len, id=pkt[IP].id, flags=pkt[IP].flags, frag=pkt[IP].frag, ttl=pkt[IP].ttl, proto=pkt[IP].proto, chksum=pkt[IP].chksum, src=pkt[IP].src, dst=pkt[IP].dst) / TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, seq=pkt[TCP].seq, ack=pkt[TCP].ack, dataofs=pkt[TCP].dataofs, reserved=pkt[TCP].reserved, flags=pkt[TCP].flags, window=pkt[TCP].window, chksum=pkt[TCP].chksum, urgptr=pkt[TCP].urgptr))
            new_pkt.time = pkt.time
            
            # Write the modified packet to the output PCAP file
            wrpcap(output_directory_path + file_name + "_replaced.pcap", new_pkt, append=True)
            
# Print the total number of processed packets
print("Total packets processed:", len(files))
