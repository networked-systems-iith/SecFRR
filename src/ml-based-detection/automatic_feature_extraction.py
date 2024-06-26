import csv
import json
import hashlib
from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict
from statistics import mean, stdev

# Define a function to calculate 5-tuple hash
def calculate_five_tuple_hash(packet):
    proto = packet.proto
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = 0
    dst_port = 0
    if proto == 6:  # TCP
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif proto == 17:  # UDP
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    five_tuple = str(src_ip) + str(dst_ip) + str(src_port) + str(dst_port)
    return five_tuple

# Define a function to extract features from a packet


# predefined features
def extract_features():
    features = {
        'Flow Duration': 0,  # Duration will be calculated during aggregation
        'Total Fwd Packets': 0,
        'Total Length of Fwd Packets': 0,
        'Packet length': 0,
        'Fwd Packet Length Max': 0,
        'Fwd Packet Length Min': 9999999, #float('inf'),
        'Fwd Packet Length Mean': 0,
        #'Fwd Packet Length Std': 0,
        'Flow Bytes/s': 0,
        'Flow Packets/s': 0,
        #'Flow IAT Mean': 0,
        #'Flow IAT Std': 0,
        #'Flow IAT Max': 0,
        #'Flow IAT Min': 9999999, #float('inf'),
        'Fwd IAT Total': 0,
        #'Fwd IAT Mean': 0,
        #'Fwd IAT Std': 0,
        #'Fwd IAT Max': 0,
        #'Fwd IAT Min': 9999999, #float('inf'),
        'Fwd PSH Flags': 0,
        'Fwd URG Flags': 0,
        'Fwd Header Length': 0,
        'Fwd Packets/s': 0,
        #'Min Packet Length': 9999999, #float('inf'),
        #'Max Packet Length': 0,
        'Packet Length Mean': 0,
        #'Packet Length Std': 0,
        #'Packet Length Variance': 0,
        'FIN Flag Count': 0,
        'SYN Flag Count': 0,
        'RST Flag Count': 0,
        'ACK Flag Count': 0,
    }
    return features

# Define a function to update features for a flow
def update_features(flow_features, packet, timestamp, prev_timestamp):
    length = len(packet)
    flow_features['Total Fwd Packets'] += 1
    flow_features['Total Length of Fwd Packets'] += length
    flow_features['Packet length'] = length
    flow_features['Fwd Packet Length Max'] = max(flow_features['Fwd Packet Length Max'], length)
    flow_features['Fwd Packet Length Min'] = min(flow_features['Fwd Packet Length Min'], length)
    
    # Calculate IAT
    if prev_timestamp is not None:
        iat = float(timestamp - prev_timestamp)
        flow_features['Fwd IAT Total'] += iat
        #flow_features['Fwd IAT Max'] = float(max(flow_features['Fwd IAT Max'], iat))
        #flow_features['Fwd IAT Min'] = float(min(flow_features['Fwd IAT Min'], iat))

    # Update packet flags
    if 'TCP' in packet:
        tcp_flags = packet.sprintf('%TCP.flags%')
        flow_features['FIN Flag Count'] += tcp_flags.count('F')
        flow_features['SYN Flag Count'] += tcp_flags.count('S')
        flow_features['RST Flag Count'] += tcp_flags.count('R')
        flow_features['ACK Flag Count'] += tcp_flags.count('A')
        flow_features['Fwd PSH Flags'] += tcp_flags.count('P')
        flow_features['Fwd URG Flags'] += tcp_flags.count('U')
    
    # Update header length
    if 'IP' in packet:
        flow_features['Fwd Header Length'] += packet[IP].ihl * 4

input_folder = 'E:\\IITH\\BLINK\\CAIDA\\automatic-feature-extraction\\attack\\'



pcap_file = # trace
log_file = # state file
ret_file = # state file



window_size = 0.6  # seconds
flows = defaultdict(lambda: {'features': extract_features(), 'timestamps': []})


ret_values = []
with open(input_folder + ret_file, 'r') as f:
    reader = csv.reader(f)
    for row in reader:
        ret_values.append(row[0])


with open(input_folder + log_file, 'r') as f:
    hash_lists = [line.split(',') for line in f.read().splitlines()]
    # print(hash_lists)

    
    # Open CSV file for writing
with open(input_folder + 'new\\' + pcap_file + '.csv', 'w', newline='') as csvfile:
    fieldnames = [
        'State', 'Flow ID', 'Flow Duration', 'Total Fwd Packets', 'Total Length of Fwd Packets', 'Packet length', 
        'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
        'Flow Bytes/s', 'Flow Packets/s',
        'Fwd IAT Total', 'Fwd PSH Flags', 'Fwd URG Flags',
        'Fwd Header Length', 'Fwd Packets/s',
        'Packet Length Mean', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'ACK Flag Count', 'label'
    ]

    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()

    # Read packets from pcap file
    packets = rdpcap(input_folder + pcap_file)
    start_time = packets[0].time
    current_window = start_time + window_size
    ind = 0
    ret_ind = 1

    # Process packets
    for packet in packets:
        #print(packet)
        timestamp = packet.time

        if timestamp > current_window:
            current_window += window_size
            ind += 1
            ret_ind += 1
        
        hash_val = calculate_five_tuple_hash(packet)
        #print(hash_val)
        if ind == len(hash_lists):
            break

        if hash_lists[ind] == ['']:
            continue

        set_hash_lists = set(hash_lists[ind])
        print(set_hash_lists)
        if hash_val in set_hash_lists:
            if hash_val in flows:
                prev_timestamp = flows[hash_val]['timestamps'][-1] if flows[hash_val]['timestamps'] else None
                update_features(flows[hash_val]['features'], packet, timestamp, prev_timestamp)
                flows[hash_val]['timestamps'].append(timestamp)
            else:
                flows[hash_val]['features'] = extract_features()
                flows[hash_val]['timestamps'].append(timestamp)
                prev_timestamp = None
                update_features(flows[hash_val]['features'], packet, timestamp, prev_timestamp)

            features = flows[hash_val]['features']
            features['Flow Duration'] = float(timestamp - flows[hash_val]['timestamps'][0]) if flows[hash_val]['timestamps'] else float(0)
            #features['Flow IAT Mean'] = mean(features['Flow IAT']) if 'Flow IAT' in features else 0
            #features['Fwd IAT Mean'] = features['Fwd IAT Total'] / (features['Total Fwd Packets'] - 1) if features['Total Fwd Packets'] > 1 else 0
            #features['Fwd IAT Mean'] = mean(features['Fwd IAT Total']) if 'Fwd IAT' in features else 0
            #features['Flow IAT Mean'] = mean(features['Flow IAT']) if 'Flow IAT' in features else 0
            features['Fwd Packet Length Mean'] = features['Total Length of Fwd Packets'] / features['Total Fwd Packets'] if features['Total Fwd Packets'] > 0 else 0
            features['Packet Length Mean'] = features['Total Length of Fwd Packets'] / features['Total Fwd Packets'] if features['Total Fwd Packets'] > 0 else 0
            features['Flow Packets/s'] = features['Total Fwd Packets'] / features['Flow Duration'] if features['Flow Duration'] > 0 else 0
            features['Flow Bytes/s'] = features['Total Length of Fwd Packets'] / features['Flow Duration'] if features['Flow Duration'] > 0 else 0
            features['Fwd Packets/s'] = features['Total Fwd Packets'] / features['Flow Duration'] if features['Flow Duration'] > 0 else 0
            #features['Packet Length Std'] = stdev([length for length in features['Fwd IAT']]) if 'Fwd IAT' in features and len(features['Fwd IAT']) > 1 else 0

            row = {'State': ret_values[ret_ind], 'Flow ID': hash_val, 'label': 0}
            #print(row)
            row.update(features)
            writer.writerow(row)




