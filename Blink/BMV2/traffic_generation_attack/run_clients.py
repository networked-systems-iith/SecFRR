import time
import argparse
import multiprocessing
from traceback import print_list
from .flowlib import sendFlowTCP
from .flowlib import sendFlowTCP_attack
import logging
import logging.handlers
from numpy import random
import numpy as np
from multiprocessing import Manager, Value


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

    bw_per_flow = ((bw*1000*1000)/(8.37 * flow_rate))  #bits / sec
    print("\n bw_per_flow: ", bw_per_flow, "bits/sec")

    avg_flow_size = 8.37 * bw_per_flow # bits
    print("\n avg_flow_size: ", avg_flow_size, "bits")
    # print("\n avg_flow_size: ", avg_flow_size * 20/flow_count, "bits")

    # return avg_flow_size * 20/flow_count
    return bw_per_flow

def normal_dist(mean, sd, fc):
    bw_per_flow = do_calculations() # in bits

    # Normal distribution of time(in sec) for which every flow will be active.
    norm_sec = np.random.normal(mean, sd, fc)
    norm_traffic = []
    
    for i in norm_sec:
      norm_traffic.append(bw_per_flow * round(i,1))

    return norm_traffic

process_list = []
# p_list= []

# logger.setup_logger('traffic_generation', log_dir+'/traffic_generation.log', level=logging.INFO)
# log = logging.getLogger('traffic_generation')

index = 0
norm_array = normal_dist(8.37, 1, flow_count)
start_time = time.time()

count = 0
f = open('active_flow_count.txt','w')

# sleep_time_normal = np.random.normal(1000/flow_rate, 1, flow_count)

# print(sleep_time_normal)
counter = 1
attack_port_temp = 0
for src_port, dst_port in zip(range(int(src_ports.split(',')[0]), int(src_ports.split(',')[1])), \
    range(int(dst_ports.split(',')[0]), int(dst_ports.split(',')[1]))):

    
     
    #if counter % 20 == 0:
	    #print("Hi")
        #flow_template = {"dst": dst_ip,
                     #"dport": attack_port_temp,
                     #"sport": attack_port_temp,
                     #"ipd":ipd,
                     #}

        #process = multiprocessing.Process(target=sendFlowTCP_attack, kwargs=flow_template)
        #process.daemon = True
        #process.start()
        #attack_port_temp = attack_port_temp + 1
        
    #else:
        # conc_flows = Value('i', 0)
    flow_template = {"dst": dst_ip,
                     "dport": dst_port,
                     "sport": src_port,
                     "ipd":ipd,
                     "duration": duration,
                     "fl_size": int(norm_array[index])
                    #  ,"conc_flows":conc_flows
                     }

    process = multiprocessing.Process(target=sendFlowTCP, kwargs=flow_template)
    process.daemon = True
    process.start()
    
        # time.sleep(sleep_time_normal[index]/1000)

    time.sleep(0.02)
    if index % 160 == 0:# and index ! = 0: #, otherwise it waits for 10 secs for the first flow
        time.sleep(20)
            # time.sleep(10)

            # time.sleep(1/180)
            # if index % 180 == 0:
            #     time.sleep(8.37)
            #     # time.sleep(10)


            # time.sleep(1/flow_rate)
            # cur_time = time.time()
            # if time.time() - start_time < 2:
            #     time.sleep(1/80)
            # else:
            #     time.sleep(1/flow_rate)

            # log.info('Sender started for sport: '+str(src_port)+' dport: '+str(dst_port)+ \
            # ' ipd: '+str(ipd)+' duration: '+str(duration))
    process_list.append(process)

    count = count +1
    if count % 160 == 0 : #generate attack flow after every 20
        c = 0
        for i in process_list:
            if i.is_alive():
                c = c+1    
        f.write(str(c)+"\n")
        print(count/flow_rate,"sec,  Alive processes: ", c)        
    index = index + 1
counter = counter + 1
f.close()

# alive = []
# s_time = time.time()
# for p in process_list:
#     if p.is_alive and time.time() - s_time < 1:
#         alive.append(1)
#     else:
#         print("Active flows: ",len(alive))
#         alive = []
#         s_time = time.time()
#         continue


for p in process_list:
    
    p.join()
    
