from scapy.all import Ether, IP, TCP, wrpcap, rdpcap, RandIP
import random
import time
import socket
import operator
import mmh3
import math
import pandas as pd

# PCAP file to save the packets
pcap_file = "E:\\IITH\\BLINK\\CAIDA\\RoutScout\\codes\\attack-new\\A2\\60secs\\attack-132500-top2-A2-1%.pcap"

# ATTACK TYPE 2
# RELEASE ACKS AT THE SAME TIME


# Average delay 
avg_delay = 0.305

# Number of SYN packets to send
num_attack_flows = 23 #23  # Adjust this as needed, currently 1%
duration = 10

# Minimum and maximum possible delays
min_delay =  (2*avg_delay)
max_delay = (32*avg_delay)

# # Generate a list of delays with a uniform distribution
ack_delays = [random.uniform(min_delay, max_delay) for _ in range(num_attack_flows)]


# Create a list to store the packets
packets = []
hash = []


# Define the range within which the hash_key should fall
hash_key_range1 = (0, 105000)

# Initialize a dictionary to track SYN packets and their send times
syn_dict = {}
count = 0

ack_release_times = max_delay

for j in range(1, 9):
#for j in ack_release_times and j <= 60:
    if j*ack_release_times < 60:
        print(j)
        for i in range(num_attack_flows):
            while True:
                # Generate a random source IP address
                src_ip = f"{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
                
                # Generate a destination IP address starting with "213.173"
                dest_ip = f"213.173.{random.randint(0, 255)}.{random.randint(0, 255)}"

                src_port = random.randint(1024, 65535)  # Random source port between 1024 and 65535
                dest_port = random.randint(1, 1023)

                # Generate a random protocol (e.g., TCP = 6)
                protocol = 6

                # Construct the key
                key = str(src_ip) + str(dest_ip) + str(src_port) + str(dest_port) + str(protocol)

                # Calculate the hash_key
                hash_key = mmh3.hash(key) % (int(math.pow(2, 20)) - 1) + 1

                # Check if the hash_key is within the desired range
                if hash_key_range1[0] < hash_key < hash_key_range1[1]:
                    break
            
            syn_packet = Ether() / IP(src=src_ip, dst=dest_ip) / TCP(sport=src_port, dport=dest_port, flags="S")
            
            random.shuffle(ack_delays)
            ack_delay = random.choice(ack_delays)
            ack_packet = Ether() / IP(src=syn_packet[IP].src, dst=syn_packet[IP].dst) / TCP(sport=syn_packet[IP].sport, dport=syn_packet[IP].dport, flags="A")
            ack_packet.time = float(j*ack_release_times)
            syn_packet.time = ack_packet.time - ack_delay
                
            packets.append(syn_packet)
            packets.append(ack_packet)
         


sorted_packets = sorted(packets, key=operator.attrgetter("time"))

# Save the packets to a PCAP file
wrpcap(pcap_file, sorted_packets)

print(f"SYN and ACK packets saved to {pcap_file}.")

