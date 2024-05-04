from scapy.all import *
import ipaddr
import mmh3

TH_FIN = 0b1
TH_SYN = 0b10
TH_RST = 0b100
TH_PUSH = 0b1000
TH_ACK = 0b10000
TH_URG = 0b100000
TH_ECE = 0b1000000
TH_CWR = 0b10000000


#main.py code
from DelayMonitor1 import IBLT

capacity=781500
delay_aggregatorA = [0,0]
delay_aggregatorB = [0,0]

delayMon = IBLT()
delayMon._init_(781500,0.001,9)

#forward and monitor
forw_flowsA = range(0,518)
forw_flowsB = range(518,1037)
mon_flowsA = forw_flowsA
mon_flowsB = forw_flowsB

pack_ack = []
for i in range(1037):
    pack_ack.append(0)


#adding a flow to IBLT
def pollute_IBLT_Loss(time_stamp, src_ip, src_port, dst_ip, dst_port, protocol,syn, fin,ack,payload) :

    key = str(src_ip) + str(dst_ip) + str(src_port) + str(dst_port) + str(protocol)

    hash_key = hash(key)%1037
    if (hash_key in mon_flowsA) or (hash_key in mon_flowsB) :
        if syn==1 and ack==0:
            delayMon._insert_(key,time_stamp)
            
            pack_ack[hash_key] = 1
            
        elif fin==False and pack_ack[hash_key]==1 and payload==0:
            delay = delayMon._delete_(key,time_stamp)
            
            if delay==-1:
                return
            if hash_key in mon_flowsA :
                delay_aggregatorA[0] += delay
                delay_aggregatorA[1] += 1
            elif hash_key in mon_flowsB :
                delay_aggregatorB[0] += delay
                delay_aggregatorB[1] += 1
            pack_ack[hash_key] = 0
    return hash_key


#parsing of pcap

def get_timestamp(meta, format="pcap"):
    if format == "pcap":
        return meta.sec + meta.usec/1000000.
    elif format == "pcapng":
        return ((meta.tshigh << 32) | meta.tslow) / float(meta.tsresol)

def ipv6_to_ipv4(ipv6):

    hashed = hash(ipv6) & 0xfffffff
    ip = ipaddr.IPv4Address(hashed)
    return ip.compressed

def pcap_reader(in_file):
    """
    Args:
        in_file:
        packets_to_process:
    Returns:
    """

    #constants
    IP_LEN = 20
    IPv6_LEN = 40
    TCP_LEN = 14

    delayA = []
    delayB = []

    #variables
    _pcap_reader = RawPcapReader(in_file)
    #helper to read PCAP files (or pcapng)

    first_packet = True
    default_packet_offset = 0
    

    #packets count
    pack_pro = 0
    pack_syn = 0
    ack_pack = 0
    pre_time = 0
    total_pack = 0

    #pack_del = 0
    ##

    for packet, meta in _pcap_reader:
        try:
            if first_packet:
                first_packet = False
                # check if the metadata is for pcap or pcapng
                if hasattr(meta, 'usec'):
                    pcap_format = "pcap"
                    link_type = _pcap_reader.linktype
                elif hasattr(meta, 'tshigh'):
                    pcap_format = "pcapng"
                    link_type = meta.linktype

                # check first layer
                if link_type == DLT_EN10MB:
                    default_packet_offset += 14
                elif link_type == DLT_RAW_ALT:
                    default_packet_offset += 0
                elif link_type == DLT_PPP:
                    default_packet_offset += 2


            #remove bytes until IP layer (this depends on the linktype)
            packet = packet[default_packet_offset:]
            #packet = packet[0:]

            #IP LAYER Parsing
            packet_offset = 0
            version = struct.unpack("!B", packet[0:1])
            ip_version = version[0] >> 4
            if ip_version == 4:
                # filter if the packet does not even have 20+14 bytes
                if len(packet) < (IP_LEN + TCP_LEN):
                    continue
                #get the normal ip fields. If there are options we remove it later
                ip_header = struct.unpack("!BBHHHBBHBBBBBBBB", bytes(packet[:IP_LEN]))
                #increase offset by layer length
                ip_header_length = (ip_header[0] & 0x0f) * 4

                packet_offset += ip_header_length

                ip_length = ip_header[2]

                protocol = ip_header[6]
                #filter protocols
                if protocol != 6:
                    continue
                #format ips
                ip_src = '{0:d}.{1:d}.{2:d}.{3:d}'.format(ip_header[8],
                                                    ip_header[9],
                                                    ip_header[10],
                                                    ip_header[11])
                ip_dst = '{0:d}.{1:d}.{2:d}.{3:d}'.format(ip_header[12],
                                                    ip_header[13],
                                                    ip_header[14],
                                                    ip_header[15])
            #parse ipv6 headers
            elif ip_version == 6:
                # filter if the packet does not even have 20+14 bytes
                if len(packet) < (IPv6_LEN + TCP_LEN):
                    #log.debug("Small packet found")
                    continue
                ip_header = struct.unpack("!LHBBQQQQ", bytes(packet[:40]))
                #protocol/next header
                ip_length = 40 + ip_header[1]
                ip_header_length = 40
                protocol = ip_header[2]
                if protocol != 6:
                    continue
        
                ip_src = ipv6_to_ipv4(ip_header[4] << 64 | ip_header[5])
                ip_dst = ipv6_to_ipv4(ip_header[6] << 64 | ip_header[7])
                packet_offset +=40

            else:
                continue

            #parse TCP header
            
            tcp_header = struct.unpack("!HHLLBB", bytes(packet[packet_offset:packet_offset+TCP_LEN]))
            sport = tcp_header[0]
            dport = tcp_header[1]
            pkt_seq = tcp_header[2]
            tcp_header_length = ((tcp_header[4] & 0xf0) >> 4) * 4
            flags = tcp_header[5]
            syn_flag = flags & TH_SYN != 0
            fin_flag = flags & TH_FIN != 0
            ack_flag = flags & TH_ACK != 0

            #update data structures
            packet_ts = get_timestamp(meta, pcap_format)

            tcp_payload_length = ip_length - ip_header_length - tcp_header_length

            
            
            key = pollute_IBLT_Loss(packet_ts, ip_src, sport, ip_dst, dport, protocol, syn_flag, fin_flag,ack_flag,tcp_payload_length)
            
            if (key in mon_flowsA) or (key in mon_flowsB) :
                pack_pro += 1
                if syn_flag and ack_flag==0:
                    pack_syn += 1
                if fin_flag==False and tcp_payload_length==0 and ack_flag==1 and syn_flag==0 and pkt_seq==0:
                    ack_pack += 1
            
            #for every one second, sum of delays and no. of packets are returned
            if packet_ts-pre_time >= 1:
                pre_time = packet_ts
                total_pack += (delay_aggregatorA[1] + delay_aggregatorB[1])
                delA =delB= 0
                if delay_aggregatorA[1]!=0:
                    delA = delay_aggregatorA[0]/delay_aggregatorA[1]
                if delay_aggregatorB[1]!=0:
                    delB = delay_aggregatorB[0]/delay_aggregatorB[1]
                
                delayA.append(delA)
                
                delayB.append(delB)
                delay_aggregatorA[0]=0.0
                delay_aggregatorA[1]=0
                delay_aggregatorB[0]=0.0
                delay_aggregatorB[1]=0
            

        except Exception:
            #if this prints something just ingore it i left it for debugging, but it should happen almost never
            import traceback
            traceback.print_exc()


    #printing average delays at every second and perecentage change in delays wrt previous second
    if delay_aggregatorA[1]!=0 : delayA.append(delay_aggregatorA[0]/delay_aggregatorA[1]) 
    else: delayA.append(0.0)
    if delay_aggregatorA[1]!=0 : delayB.append(delay_aggregatorB[0]/delay_aggregatorB[1])
    else: delayB.append(0.0)
    print(total_pack+delay_aggregatorA[1]+delay_aggregatorB[1])
    print('total=',pack_pro)
    print('syn=',pack_syn)
    print('ack=',ack_pack)
    print('            ')
    print(delayA)
    print(delayB)
    print('                 ')

    perDelA = []
    perDelB = []
    for i in range(2,len(delayB)):
        if delayA[i-1]!=0: perDelA.append(((delayA[i]-delayA[i-1])/delayA[i-1])*100)
        else: perDelA.append(0.0)
        if delayB[i-1]!=0: perDelB.append(((delayB[i]-delayB[i-1])/delayB[i-1])*100)
        else: perDelB.append(0.0)
    print(perDelA)
    print(perDelB)