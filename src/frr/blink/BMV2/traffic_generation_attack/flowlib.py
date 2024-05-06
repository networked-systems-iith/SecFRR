import socket
import struct
import time
import subprocess, os , signal
import random
from multiprocessing import Manager, Value, Array
from scapy.all import *
port_array = []
ts_array = []
f_count = int()

def read_fcount():
    global fcount
    # print(f_count)
    return f_count
def send_msg(sock, size):

    # msg = 'a'.encode('utf-16') * int(32768*size) #4 Byte string in python #Sending 1Kbit
    # msg = "a" * 4 #34 bytes, 272 bits, 272 x 4 = 1088(approx 1Kbits)
    msg = "a"*130000 # 1 Mbits
    sock.sendall(msg.encode())

def sendFlowTCP(dst="10.0.32.3",sport=5000,dport=5001,ipd=1,duration=0,fl_size = 1,conc_flows=Value('i', 0)):

    global port_array
    global ts_array
    global f_count

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    #s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    #s.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 1500)

    s.bind(('', sport))

    try:
        reconnections = 5
        while reconnections:
            try:
                s.connect((dst, dport))
                break
            except:
                reconnections -=1
                print("TCP flow client could not connect with server... Reconnections left {0} ...".format(reconnections))
                time.sleep(0.5)

        #could not connect to the server
        if reconnections == 0:
            return

        
        pkt_count = 0
        # print(">>>fl_size(bits): ", fl_size) # As per the normal distribution value.
        fl_size = fl_size / (1024*1024) # in Mbits
        flow_size = fl_size # in Mbits
        avg_throughput = 0
        
        start_time = time.time()
        # conc_flows.value = conc_flows.value + 1
        
        while(fl_size>0):
            send_msg(s,1) #Send 1 Kbits
            fl_size = fl_size - 1
            # print(sport,"<-->",dport," fl_size",fl_size,"Last msg time:",time.time()-start_time, "pkt_count: ", pkt_count)
            f_count = conc_flows.value

            # print("concurrent flows: ", conc_flows.value)
            if fl_size <= 1 and fl_size > 0:
                # send_msg(s,fl_size) #Send last msg
                # dur = time.time()-start_time
                # per_fl_throughput = flow_size/dur
                # print(sport,"<-####->",dport," fl_size(Mbits): ",flow_size,"Flow duration: ",dur, "pkt_count: ", pkt_count, "throughput(bits/sec): ", per_fl_throughput)
                
                pass
            pkt_count = pkt_count + 1
        # conc_flows.value = conc_flows.value - 1
        stop_time = time.time()
        # print(sport,"<-####->",dport," | fl_size(Mbits): ",flow_size," | Start: ",start_time, " | Stop: ",stop_time, " | Flow duration: ",stop_time-start_time, " | throughput(Mbits/sec): ", flow_size/(stop_time-start_time))
        print("Flow duration: ",stop_time-start_time," | fl_size(Mbits): ",flow_size)
        # print("Flow duration: ",stop_time-start_time)

        # print(sport,"<-->",dport," Throughput of flow: ", flow_size/(stop_time-start_time), "bits/sec")

        # print(sport,"<-->",dport," duration:",stop_time-start_time, "pkt_count: ", pkt_count)
        # port_array.append(sport)
        # ts_array.append(stop_time-start_time)

        
        # totalTime = int(duration)

        # startTime = time.time()
        # i = 0
        # time_step = 1
        # while (time.time() - startTime <= totalTime):
        #     send_msg(s,1024)n #Send 1 Kbits
        #     i +=1
        #     next_send_time = startTime + i * ipd
        #     time.sleep(max(0,next_send_time - time.time()))

    except socket.error:
        pass

    finally:
        s.close()


def sendFlowTCP_attack(dst="10.0.32.3",sport=5000,dport=5001,ipd=1):
    '''# SYN packet
    ip=IP(src='10.0.1.1',dst=dst)
    SYN=TCP(sport=sport,dport=dport,flags='S',seq=0)
    SYNACK=sr1(ip/SYN)

    # ACK
    ACK=TCP(sport=sport, dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
    send(ip/ACK)
    '''
    rpps = random.randint(1, 10)
    ip = IP(src='10.0.1.1', dst=dst)
    tcp = Ether()/ ip / TCP(sport=sport, dport=dport, flags="PA", seq=1, ack=1) / "a"               #SYNACK.ack, ack=SYNACK.seq + 1) / "a"
    #tcp.show2()
    sendpfast(tcp, pps = rpps, realtime=None, loop = 100000000,  file_cache=False, iface=None, replay_args=None, parse_results=False) # pps = 100, changed to 2
    #send(tcp)

     
    #while(True):
        #send(tcp) #, pps = 100) # Can have sr1 here, so that sender will wait for ack and wireshark won't flag [TCP ACK UNSEEN]
        #print('Attack data sent')
        #time.sleep(0.02)
    '''
    counter = 1
    flag = 1
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.setsockopt(socket.SOL_IP, socket.IP_TTL, 1)

    s.bind(('', sport))

    try:
        reconnections = 5
        while reconnections:
            try:
                s.connect((dst, dport))
                print("Connected")
                break
            except:
                reconnections -=1
                print("TCP flow client could not connect with server... Reconnections left {0} ...".format(reconnections))
                time.sleep(0.5)

        #could not connect to the server
        if reconnections == 0:
            return

        
        
        #s.send(b'\x0a') # sends 1 Byte of data
        #s.setsockopt(socket.SOL_IP, socket.IP_TTL, 1)


        while(True):
            
            if counter == 1: # Normal packet
                s.setsockopt(socket.SOL_IP, socket.IP_TTL, 64)
                s.send(b'\x0a') # sends 1 Byte of data
                flag = 0
            elif counter == 0: # Inducing fake retransmission
                s.setsockopt(socket.SOL_IP, socket.IP_TTL, 3)
                s.send(b'\x0a') # sends 1 Byte of data
                s.setsockopt(socket.SOL_IP, socket.IP_TTL, 64) # Set ttl = 64 in order to make the TCP retransmitted packet reach Rx
                flag = 1

            if flag == 0:
                counter = 0 # if flag is 0, counter is 0 i.e ttl = 2
            elif flag == 1:
                counter = 1 # if flag is 1, counter is 1 i.e ttl = 64
                     
            if socket.IP_TTL == 1:
            #s.setsockopt(socket.SOL_IP, socket.IP_TTL, 3)
                s.send(b'\x0a') # sends 1 Byte of data
            #time.sleep(0.02)
                s.setsockopt(socket.SOL_IP, socket.IP_TTL, 64) # Set ttl = 64 in order to make the TCP retransmitted packet reach Rx  
            elif socket.IP_TTL == 64:
                s.send(b'\x0a') # sends 1 Byte of data
                s.setsockopt(socket.SOL_IP, socket.IP_TTL, 1)
            print('Attack data sent')
            
            s.send(b'\x0a')
            time.sleep(0.02)
            
            #send_msg(s,1) #Send 1 Kbits

            s.send(b'\x0a') # sends 1 Byte of data
            print('Attack data sent')
            time.sleep(0.02)
        
        #payload = "test"
        #pkt = IP(len=16384, src='10.0.1.1', dst=dst,
        #id=RandShort(), ttl=64)/TCP(sport=sport,
        #dport=sport, window=200,
        #options=[('MSS', 1460), ('WScale', 2)])/payload

        #spkt = str(pkt)
        #while(True):
            #s.sendall(spkt.encode('utf-8'))
        
    except socket.error:
        pass

    finally:
        s.close()
    '''
def recvFlowTCP(dport=5001,**kwargs):

    """
    Lisitens on port dport until a client connects sends data and closes the connection. All the received
    data is thrown for optimization purposes.
    :param dport:
    :return:
    """

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    # s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    s.bind(("", dport))
    s.listen(1)
    conn = ''
    buffer = bytearray(8750000)
    try:
        conn, addr = s.accept()
        while True:
            #data = recv_msg(conn)#conn.recv(1024)
            if not conn.recv_into(buffer,8750000):
                break

    finally:
        if conn:
            conn.close()
        else:
            s.close()
