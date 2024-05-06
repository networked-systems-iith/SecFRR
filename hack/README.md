The table gives a quick overview of the sections covered in the README and their respective descriptions.

| Section                                       | Description                                                                                                    |
|-----------------------------------------------|----------------------------------------------------------------------------------------------------------------|
| Filtering PCAP based on Relative Time         | Filter and merge PCAP files based on the relative time of capture                                              |
| Filtering PCAP based on Destination IP Prefix | Filter PCAP files based on a specific destination IP prefix                                                    |
| Top Prefixes filter based on SYN-ACKs         | Analyze PCAP files to extract top IP prefixes based on maximum SYN-ACK packets                                 |
| Filter Prefixe in PCAP Files                    | Filter all filtered prefixes PCAP files present in a folder using `tshark`                                      |
| Replace TCP Layer in PCAP Files               | Replace the TCP layer in PCAP files to address missing Ethernet headers when replayed over an interface        |
| Simultaneous Packet Replay of Normal and Attack | Replay packets from two different PCAP files simultaneously using threading                                  |
| Random Flow and packet Extraction Script from CAIDA  | Extract payload packet of a random flow from a pcap |

### 1. PCAP Filtering and Merging

#### Filtering PCAP based on Relative Time of Capture

To filter a Packet Capture (PCAP) file based on the relative time of capture and merge specific time intervals into one PCAP, you can use the following command with `tshark`:

```bash
tshark -r pcap_name.pcap -Y "(frame.time_relative >= 0 and frame.time_relative <= 10) and (frame.time_relative >= 20 and frame.time_relative <= 30)" -w merged_pcap.pcap
```

This command filters packets with a relative time of capture between 0 to 10 seconds and between 20 to 30 seconds. It then merges these filtered packets into a new PCAP file named `merged_pcap.pcap`.

#### Filtering PCAP based on Destination IP Prefix

To filter a PCAP based on a specific destination IP prefix, you can use the following command with `tshark`:

```bash
tshark -nr "${input_file1}" -2 -R 'ip.dst_host matches "213\.175\.\."' -w "${output_file}.pcap"
```

This command filters packets from the input PCAP file `${input_file1}` where the destination IP address matches the prefix `213.175/16`. It then writes the filtered packets to a new PCAP file named `${output_file}.pcap`.


### 2. Top Prefixes filter based on number of SYN-ACKS

The scripts for analyzing PCAP files and extracting information about the top IP prefixes based on maximum SYN-ACK packets. 

#### Files:

- **top_prefixes.py**: Contains functions for parsing PCAP files and extracting IP prefix information.
- **main.py**: Calls the `pcap_reader` function from `top_prefixes-syn-ack.py` and processes the results.
- **run.sh**: Executes `main.py` with a specific PCAP file as input.

#### Usage:

1. Place your PCAP file in the directory `/dir_to_CAIDA_pcap/`.
2. Execute the shell script `run.sh` from the terminal.

```bash
sh run.sh
```

3. The script will parse the PCAP file, extract information about IP prefixes, and generate a text file containing the sorted list of prefixes and their packet counts.

The script is useful for routescout system and can be modified to count number of retransmissions per prefix for blink.  

### 3. Filter Prefixes PCAP Files

This script filters all the filtered prefixes PCAP files present in a folder using `tshark`.

#### Usage:

1. Place the PCAP files to be filtered in the input directory.
2. Set the paths to the input and output directories in the script.
3. Run the script `filter_prefixes.sh` from the terminal.

```bash
sh filter_prefixes_from_pcap.sh
```

### 4. Replace TCP Layer in PCAP Files

This script reads PCAP files from an input directory, replaces the TCP layer in each packet, and writes the modified packets to an output directory.

#### Usage:

1. Place the PCAP files to be processed in the input directory.
2. Set the paths to the input and output directories in the script.
3. Run the script `replace_tcp.py` using Python 3.

```bash
python3 replace_payload_info.py
```

The replacement of the TCP layer in PCAP files is necessary because CAIDA traces lack payload content, which can lead to an "NOETH unknown error" when replayed directly over an interface due to missing Ethernet headers.

### 5. Simultaneous Packet Replay of Normal and Attack 

This script utilizes threading to replay packets from two different PCAP files simultaneously.

#### Usage:

1. Ensure that `tcpreplay` is installed on your system.
2. Set the appropriate network interface (like `eth0`) and PCAP file paths in the `run_normal` and `run_atk` functions.
3. Run the script using Python 3.


#### Steps to run to merge the pcaps using replace.py

Open 2 terminals in parallel: 

- In the first terminal, run:
```
sudo tcpdump -i eth0 -w name_of_the_merged_pcap.pcap
``` 
Note: Add an interface eth0 first and set the MTU to 200000. This is a one time process. Follow the instructions below: 
```
sudo ip link add eth0 type dummy
sudo ip link set dev eth0 mtu 200000
``` 

- In the second terminal, run:

```bash
python3 replay.py 
``` 

### 6. Random Flow and packet Extraction Script from CAIDA 

This script extracts flows with one payload packet from a specified normal pcap file using `tshark` and saves them as individual pcap files.

#### Usage:

1. Set the appropriate path to the attack pcap file (`attack_pcap`) and the output directory (`output_directory`).
2. Set the end value for the loop (`END`) if needed.
3. Run the script using bash.

```bash
bash pick_flows_from_pcap.sh
```

4. The script will extract attack flows from the specified pcap file and save them as individual pcap files in the output directory.

#### Notes:

- Adjust the path to the attack pcap file and the output directory as per your setup.
- The script will only extract attack flows with non-zero TCP payload length.
- You can modify the loop range by changing the `END` value according to your requirements.



