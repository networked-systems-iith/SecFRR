import os
import threading

def run_normal():
    os.system('sudo tcpreplay -i eth0  top_prefixes-132500_top2_filtered_replaced.pcap')

def run_atk():
    os.system('sudo tcpreplay -i eth0 A1-new/attack-132500-top2-A1-1RTT.pcap')


t1 = threading.Thread(target=run_normal,args=())
t2 = threading.Thread(target=run_atk,args=())

t1.start()

t2.start()

t1.join()

t2.join()