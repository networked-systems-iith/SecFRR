from scapy.all import Ether, IP, TCP, wrpcap, RandIP
import random
import operator
import mmh3
import math

# Common parameters
pcap_file = "pcap_file_to_save_attack_flows.pcap"
avg_delay = 0.305
num_attack_flows = 23
min_delay = (1.5 * avg_delay)
max_delay = (min_delay + 0.05)
hash_key_range = (0, 105000)
hash = []

# Mode A1 parameters
ack_delays_a1 = [random.uniform(min_delay, max_delay) for _ in range(num_attack_flows)]
syn_dict_a1 = {}
count_a1 = 0

# Mode A2 parameters
ack_delays_a2 = [random.uniform(2 * avg_delay, 32 * avg_delay) for _ in range(num_attack_flows)]
ack_release_times = max_delay

# Packet list
packets = []

for mode in ["A1", "A2"]:
    for j in range(60):
        if mode == "A1":
            for i in range(num_attack_flows):
                while True:
                    src_ip = f"{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
                    dest_ip = f"213.173.{random.randint(0, 255)}.{random.randint(0, 255)}"
                    src_port = random.randint(1024, 65535)
                    dest_port = random.randint(1, 1023)
                    protocol = 6
                    key = str(src_ip) + str(dest_ip) + str(src_port) + str(dest_port) + str(protocol)
                    hash_key = mmh3.hash(key) % (int(math.pow(2, 20)) - 1) + 1
                    if hash_key_range[0] < hash_key < hash_key_range[1]:
                        break
                
                syn_packet = Ether() / IP(src=src_ip, dst=dest_ip) / TCP(sport=src_port, dport=dest_port, flags="S")
                syn_packet.time = float(j)
                
                syn_dict_a1[count_a1] = (syn_packet, time.time())
                count_a1 += 1

        elif mode == "A2":
            for i in range(num_attack_flows):
                while True:
                    src_ip = f"{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
                    dest_ip = f"213.173.{random.randint(0, 255)}.{random.randint(0, 255)}"
                    src_port = random.randint(1024, 65535)
                    dest_port = random.randint(1, 1023)
                    protocol = 6
                    key = str(src_ip) + str(dest_ip) + str(src_port) + str(dest_port) + str(protocol)
                    hash_key = mmh3.hash(key) % (int(math.pow(2, 20)) - 1) + 1
                    if hash_key_range[0] < hash_key < hash_key_range[1]:
                        break
                
                syn_packet = Ether() / IP(src=src_ip, dst=dest_ip) / TCP(sport=src_port, dport=dest_port, flags="S")
                ack_delay = random.choice(ack_delays_a2)
                ack_packet = Ether() / IP(src=syn_packet[IP].src, dst=syn_packet[IP].dst) / TCP(sport=syn_packet[IP].sport, dport=syn_packet[IP].dport, flags="A")
                ack_packet.time = float(j * ack_release_times)
                syn_packet.time = ack_packet.time - ack_delay

                packets.append(syn_packet)
                packets.append(ack_packet)

# Sort packets by time
sorted_packets = sorted(packets, key=operator.attrgetter("time"))

# Save packets to PCAP file
wrpcap(pcap_file, sorted_packets)

print(f"SYN and ACK packets saved to {pcap_file}.")
