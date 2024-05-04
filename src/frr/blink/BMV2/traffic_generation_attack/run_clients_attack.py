import time
import argparse
import multiprocessing
from .flowlib import sendFlowTCP
from .flowlib import sendFlowTCP_attack
import logging
import logging.handlers
from numpy import random
import numpy as np

from util import logger

parser = argparse.ArgumentParser()
parser.add_argument('--dst_ip', nargs='?', type=str, default=None, help='Destination IP', required=True)
parser.add_argument('--src_ports', nargs='?', type=str, default=None, help='Ports range', required=True)
parser.add_argument('--dst_ports', nargs='?', type=str, default=None, help='Ports range', required=True)
parser.add_argument('--ipd', nargs='?', type=float, default=None, help='Inter packet delay', required=True)
parser.add_argument('--log_dir', nargs='?', type=str, default='log', help='Log Directory', required=False)


args = parser.parse_args()
dst_ip = args.dst_ip
src_ports = args.src_ports
dst_ports = args.dst_ports
ipd = args.ipd
log_dir = args.log_dir




process_list = []


for src_port, dst_port in zip(range(int(src_ports.split(',')[0]), int(src_ports.split(',')[1])), \
    range(int(dst_ports.split(',')[0]), int(dst_ports.split(',')[1]))):

    flow_template = {"dst": dst_ip,
                     "dport": dst_port,
                     "sport": src_port,
                     "ipd":ipd,}

    process = multiprocessing.Process(target=sendFlowTCP_attack, kwargs=flow_template)
    process.daemon = True
    process.start()

    time.sleep(0.03) # Delay between two processes


    process_list.append(process)

    

for p in process_list:
    p.join()
    
