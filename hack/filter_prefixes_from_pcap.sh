#!/bin/bash

# Script to filter all the filtered prefixes PCAP files present in a folder

# Set the input directory containing the PCAP files
input_dir='/path/to/input/directory/'

# Set the output directory for filtered PCAP files
output_dir='/path/to/output/directory/'

# Loop through each PCAP file in the input directory
for f in "$input_dir"*.pcap; do
    # Extract the file name
    file_name=$(basename "$f")
    echo "Filtering $file_name"

    # Define the output file name and path
    output_file="${output_dir}${file_name%.pcap}_filtered.pcap"

    # Filter the PCAP file using tshark
    tshark -nr "$f" -2 -R "(tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.len==0) || (tcp.flags.syn==0 && tcp.flags.ack==1 && tcp.len==0)" -w "$output_file"
done
