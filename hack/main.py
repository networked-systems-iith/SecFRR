import sys
from top_prefixes import pcap_reader

input = sys.argv[1]
sorted_packets = pcap_reader('/dir_to_CAIDA_pcap/' + input)

with open('top-prefixes_' + input + '.txt','w') as file: # store top prefixes in a txt file
    for x in sorted_packets:
        file.write(x[0]+'.0.0/16'+' : '+str(x[1])+'\n')
