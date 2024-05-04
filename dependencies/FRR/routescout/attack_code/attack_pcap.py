from scapy.all import Ether, IP, TCP, wrpcap, rdpcap, RandIP
import random
import time
import socket
import operator
import mmh3
import math
import pandas as pd

# PCAP file to save the packets
pcap_file = "E:\\IITH\\BLINK\\CAIDA\\RoutScout\\codes\\attack-new\\A1\\60secs-new\\attack-132500-top2-A1-1.5RTT.pcap"


# Average delay 
avg_delay = 0.305

# Number of SYN packets to send
num_attack_flows = 23  # Adjust this as needed, currently 1%


# Minimum and maximum possible delays
min_delay =  (1.5*avg_delay)
max_delay =  (min_delay+0.05)

# # Generate a list of delays with a uniform distribution
ack_delays = [random.uniform(min_delay, max_delay) for _ in range(num_attack_flows)]
#print(ack_delays)
#print(len(ack_delays))
#print("Total Atk delay Sum:", sum(ack_delays))


# Create a list to store the packets
packets = []
hash = []


# Define the range within which the hash_key should fall
hash_key_range1 = (0, 105000)

# Initialize a dictionary to track SYN packets and their send times
syn_dict = {}
count = 0

for j in range(0, 60): # loop for time in seconds
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
        
        hash.append(hash_key)


        # Send a SYN packet
        syn_packet = Ether() / IP(src=src_ip, dst=dest_ip) / TCP(sport=src_port, dport=dest_port, flags="S")
        syn_packet.time = float(j)
        #print(syn_packet.time)
        
        # Store the SYN packet and send time in the dictionary
        syn_dict[count] = (syn_packet, time.time())
        
        count += 1

for i in range(count):
    if i in syn_dict:
        syn_packet, send_time = syn_dict[i]
        random.shuffle(ack_delays)
        ack_delay = random.choice(ack_delays)
        print(f"The chosen delay for SYN {i + 1} is {ack_delay} seconds")
        #time.sleep(ack_delay)
        ack_packet = Ether() / IP(src=syn_packet[IP].src, dst=syn_packet[IP].dst) / TCP(sport=syn_packet[IP].sport, dport=syn_packet[IP].dport, flags="A")
        ack_packet.time = syn_packet.time + ack_delay
        #print(ack_packet.time)
        packets.append(syn_dict[i][0])
        packets.append(ack_packet)

sorted_packets = sorted(packets, key=operator.attrgetter("time"))

# Save the packets to a PCAP file
wrpcap(pcap_file, sorted_packets)

print(f"SYN and ACK packets saved to {pcap_file}.")

# df = pd.DataFrame({'Hash Values of Atk flows': hash})

# Specify the CSV file path
# csv_file = '213-173-fast_atk_hash.csv'

# Save the DataFrame to a CSV file
# df.to_csv(csv_file, index=False)

# print(f'Hash values saved to {csv_file}.')