from scapy.all import *
from scapy.utils import rdpcap, PcapReader
import os
from pathlib import Path
import glob
i=0

input = 'E:\\IITH\\BLINK\\CAIDA\\RoutScout\\codes\\attack-new\\'
import os
files = os.listdir(input)
for file in files:
    if file.endswith('.pcap'):
        pkts=rdpcap(input + file)  # change input file name
        print(pkts)
        for pkt in pkts:
            if pkt[IP].proto == 6:
                packet = (Ether()/IP(version=pkt[IP].version,ihl=pkt[IP].ihl,tos=pkt[IP].tos,len=pkt[IP].len,id=pkt[IP].id,flags=pkt[IP].flags,frag=pkt[IP].frag,ttl=pkt[IP].ttl,proto=pkt[IP].proto, chksum=pkt[IP].chksum, src=pkt[IP].src,dst=pkt[IP].dst)/TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport,seq=pkt[TCP].seq, ack=pkt[TCP].ack, dataofs=pkt[TCP].dataofs,reserved=pkt[TCP].reserved, flags=pkt[TCP].flags,window=pkt[TCP].window,chksum=pkt[TCP].chksum,urgptr=pkt[TCP].urgptr))
                packet.time = pkt.time
                wrpcap(input + 'replaced//' + 'replaced_' + file ,packet,append=True) # change output file name
                i+=1
                pkts=[]
                packet=[]