import os
import threading

def run_pcap(pcap_file, interface):
    os.system(f'sudo tcpreplay -i {interface} {pcap_file}')

# Set the paths to the PCAP files and the network interface
pcap_file_normal = "path/to/normal.pcap"
pcap_file_attack = "path/to/attack.pcap"
network_interface = "eth0"

# Create threads for replaying packets from each PCAP file
t1 = threading.Thread(target=run_pcap, args=(pcap_file_normal, network_interface))
t2 = threading.Thread(target=run_pcap, args=(pcap_file_attack, network_interface))

# Start the threads
t1.start()
t2.start()

# Wait for both threads to finish
t1.join()
t2.join()
