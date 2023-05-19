import time
import argparse
import multiprocessing
from .flowlib import sendFlowTCP
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
parser.add_argument('--duration', nargs='?', type=int, default=None, help='Duration', required=True)
parser.add_argument('--log_dir', nargs='?', type=str, default='log', help='Log Directory', required=False)
parser.add_argument('--bw', nargs='?', type=float, default='log', help='Bandwidth of the link(Mbits/sec)', required=False)
parser.add_argument('--flow_rate', nargs='?', type=int, default='log', help='Flows per second', required=False)
parser.add_argument('--flow_count', nargs='?', type=int, default='log', help='Number of flows to send', required=False)

args = parser.parse_args()
dst_ip = args.dst_ip
src_ports = args.src_ports
dst_ports = args.dst_ports
ipd = args.ipd
duration = args.duration
log_dir = args.log_dir
bw = args.bw #Mbits / sec
flow_rate = args.flow_rate #flows / sec
flow_count = args.flow_count

def do_calculations():
    print("\n No. of flows: ", flow_count)

    bw_per_flow = ((bw)/(8.37 * flow_rate))*1000  #Kbits / sec
    print("\n bw_per_flow: ", bw_per_flow, "Kbits/sec")

    avg_flow_size = 8.37 * bw_per_flow # Kbits
    print("\n avg_flow_size: ", avg_flow_size, "Kbits")

    return avg_flow_size

def normal_dist(mean, sd, fc):
    avg_flow_size = do_calculations() # in Kbits

    # Normal distribution of time(in sec) for which every flow will be active.
    norm_sec = np.random.normal(mean, sd, fc)
    norm_traffic = []
    
    for i in norm_sec:
      norm_traffic.append(avg_flow_size * round(i,1))

    return norm_traffic

process_list = []

logger.setup_logger('traffic_generation', log_dir+'/traffic_generation.log', level=logging.INFO)
log = logging.getLogger('traffic_generation')

index = 0
norm_array = normal_dist(8.34, 1, flow_count)
for src_port, dst_port in zip(range(int(src_ports.split(',')[0]), int(src_ports.split(',')[1])), \
    range(int(dst_ports.split(',')[0]), int(dst_ports.split(',')[1]))):

    flow_template = {"dst": dst_ip,
                     "dport": dst_port,
                     "sport": src_port,
                     "ipd":ipd,
                     "duration": duration,
                     "fl_size": int(norm_array[index])}

    process = multiprocessing.Process(target=sendFlowTCP, kwargs=flow_template)
    process.daemon = True
    process.start()

    time.sleep(0.05)

    log.info('Sender started for sport: '+str(src_port)+' dport: '+str(dst_port)+ \
    ' ipd: '+str(ipd)+' duration: '+str(duration))

    process_list.append(process)

    index = index + 1

for p in process_list:
    p.join()
    