
from scapy.all import *
import mmh3

import math
import random

def make_hashfuncs(num_slices, num_bits,key):
  
    seeds= [i for i in range(1,num_slices+1)]
    rval = []
    rval.extend(int(abs(mmh3.hash(key,seed))%num_bits) for seed in seeds) #hash should be changed to mmh3 mmh3.hash(key, seed)
    
    del rval[num_slices:]
    
    return rval

class LossMonitor(object):
    def __init__(self, capacity, error_rate=0.001, kl=3):

        self.capacity=capacity
        self.kl=kl
        if not (0 < error_rate < 1):
            raise ValueError("Error_Rate must be between 0 and 1.")
        if not capacity > 0:
            raise ValueError("Capacity must be > 0")
        self.lm_size=int((self.kl * self.capacity)/math.log(2))
       

        self.cells_per_slice = int(self.lm_size/self.kl)
        self.count_min_sketch=[]


        for i in range(self.lm_size):
            self.count_min_sketch.append(0)

    def setup():
        pass

    def contains(self,key):
        
        hashes=make_hashfuncs(self.kl,self.cells_per_slice,key)
        offset = 0
        
        for k in hashes:
            if self.count_min_sketch[offset+k] < 1:
                return False
            offset+=self.cells_per_slice
            return True

    def insert(self,key):                      # this function is used to insert the next expected packet of the sequence (note: next expected packet not the curren one)
                
        hashes=make_hashfuncs(self.kl,self.cells_per_slice,key)
        offset = 0
        
        for k in hashes:
            self.count_min_sketch[k+offset] = self.count_min_sketch[k+offset] + 1
            offset += self.cells_per_slice
            

    def verify_expectation(self,key, index=0): #this index for now denotes the next hop , by default i am taking it as 0 which is the first hop A
        
        hashes=make_hashfuncs(self.kl,self.cells_per_slice,key)
        
        offset = 0
        result=[]
        
        for k in hashes:
            result.append(self.count_min_sketch[offset+k])
            offset+=self.cells_per_slice

        

        for i in range(len(result)):
            if result[i] < 1:
                return False

        return True

    def delete(self,key):
        hashes=make_hashfuncs(self.kl,self.cells_per_slice,key)
        offset = 0
        for k in hashes:
            self.count_min_sketch[k+offset] = self.count_min_sketch[k+offset] - 1
            offset += self.cells_per_slice


# start_seq_number=100
# packet1=IP(dst='8.8.8.8',ihl=5,len=30)/TCP(seq=start_seq_number,dataofs=0)
# packet1.show()

# ip_hdr_len=packet1.ihl
# tcp_data_offset=packet1.dataofs
# packet_length=packet1.len

# print(ip_hdr_len)
# print(tcp_data_offset)
# print(packet_length)

# tcp_payload=packet_length-4*(ip_hdr_len)-4*tcp_data_offset
# print(tcp_payload)

# packet2=IP(dst='8.8.8.8',ihl=5,len=30)/TCP(seq=packet1.seq+tcp_payload,dataofs=0)
# packet2.show()


# packet3=IP(dst='9.9.9.9',ihl=5,len=30)/TCP(seq=start_seq_number,dataofs=0)
# packet3.show()
# # packet3=IP(dst='8.8.8.8')/TCP(seq=200,FIN=0)


# packet4=IP(dst='8.8.8.8',ihl=5,len=30)/TCP(seq=packet2.seq+tcp_payload,dataofs=0)
# packet4.show()

# created_packets=[packet1,packet2,packet3,packet4]
# my_object=LossMonitor(20,0.001,9)
# print(my_object.count_min_sketch)

# my_dict={}
# for packet in created_packets:
#   key=str(packet.src)+str(packet.dst)+str(packet.sport)+str(packet.dport)+str(packet.proto)
#   if my_dict.get(key) is None: #the packet is the first packet of the flow
#     my_dict[key]=1

#     tcp_payload=packet.len-4*(packet.ihl)-4*(packet.dataofs)
#     next_sequence_number=packet.seq+tcp_payload
#     six_tuple_key=key+str(next_sequence_number)
#     my_object.insert(six_tuple_key)
  
#   else:
#     current_sequence_number=packet.seq
#     six_tuple_key=key+str(current_sequence_number)
#     if my_object.verify_expectation(six_tuple_key)==True:

#       my_object.delete(six_tuple_key)   #cleaning of loss monitor

#       tcp_payload=packet.len-4*(packet.ihl)-4*(packet.dataofs)
#       next_sequence_number=packet.seq+tcp_payload
#       next_six_tuple_key=key+str(next_sequence_number)      #inserting next packet of the flow

#       my_object.insert(next_six_tuple_key)
