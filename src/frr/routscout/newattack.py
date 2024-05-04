from scapy.all import wrpcap, Ether, IP, TCP
import time
from scapy.utils import PcapWriter
import random


# pack_req = 270
# tot_pack = pack_req*2
pack_per_sec = 16

global t
t = 0.0

pktdump = PcapWriter('delay_5_pack_16.pcap',append=True,sync=True)

def send_syn_ack_set(pack_per_sec):
    src_ips = ['10.0.39.1','10.0.39.2','10.0.39.3','10.0.39.4','10.0.39.5','10.0.39.6']
    dst_ip_first = '237.42.73.'
    src_p = [20,40,60,30,90]
    dst_p = [80,100,50,70,10]
    syns_sent = []
    global t
    pre_time = t
    for i in range(5):
        for i in range(pack_per_sec):
            src_ip = random.choice(src_ips)
            last_num = random.randint(0,200)
            dst_ip = dst_ip_first + str(last_num)
            src_pr = random.choice(src_p)
            dst_pr = random.choice(dst_p)
            syns_sent.append([src_ip,dst_ip,src_pr,dst_pr])
            packet = Ether()/IP(src=src_ip,dst=dst_ip,version=4,ihl=None,tos=0,len=None,id=1,flags=0,frag=0,ttl=64,proto=6,chksum=None)/TCP(sport=src_pr,dport=dst_pr,seq=0,ack=0,flags='S',dataofs=None,window=63555,chksum=None)
            packet.time = t
            pktdump.write(packet)
            t += 0.06
        t = pre_time + 1.0
        if t==60.0:
            break
        pre_time = t
    print(t)

    ind = 0
    for i in range(55):
        if t==60.0:
            break
        for i in range(pack_per_sec):
            pack = syns_sent[ind]
            src_ip_a = pack[0]
            dst_ip_a = pack[1]
            src_pr_a = pack[2]
            dst_pr_a = pack[3]

            packeta = Ether()/IP(src=src_ip_a,dst=dst_ip_a,version=4,ihl=None,tos=0,len=None,id=1,flags=0,frag=0,ttl=64,proto=6,chksum=None)/TCP(sport=src_pr_a,dport=dst_pr_a,seq=1,ack=1,flags='A',dataofs=None,window=63555,chksum=None)
            packeta.time = t
            pktdump.write(packeta)
            ind +=1

            src_ip = random.choice(src_ips)
            last_num = random.randint(0,200)
            dst_ip = dst_ip_first + str(last_num)
            src_pr = random.choice(src_p)
            dst_pr = random.choice(dst_p)
            syns_sent.append([src_ip,dst_ip,src_pr,dst_pr])
            packet = Ether()/IP(src=src_ip,dst=dst_ip,version=4,ihl=None,tos=0,len=None,id=1,flags=0,frag=0,ttl=64,proto=6,chksum=None)/TCP(sport=src_pr,dport=dst_pr,seq=0,ack=0,flags='S',dataofs=None,window=63555,chksum=None)
            packet.time = t
            pktdump.write(packet)

            t += 0.06

        t = pre_time + 1.0
        pre_time = t


send_syn_ack_set(pack_per_sec)
print(t)
packet = Ether()/IP(src='10.0.1.4',dst='237.42.73.66',version=4,ihl=None,tos=0,len=None,id=1,flags=0,frag=0,ttl=64,proto=6,chksum=None)/TCP(sport=20,dport=40,seq=0,ack=0,flags='S',dataofs=None,window=63555,chksum=None)
packet.time = t
pktdump.write(packet)