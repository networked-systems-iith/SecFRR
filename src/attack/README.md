
## Blink's fake restranmission Attack Simulation

This Python script reads PCAP files containing attack traffic, adjusts the timestamps, and generates attack traffic by sending same packet creating fake retransmissions at a rate of 10 flows per second.

#### Usage


1. **Run the Script**

   - Execute the Python script `blink-attack.py`:
     ```bash
     python blink-attack.py
     ```

2. **Review Output**

   - The script will generate attack traffic at a rate of 10 flows per second and save it to a PCAP file named `attack_each_sec_newflow_new.pcap` in the specified result directory.

For more details, follow Section III of our [paper](link)

## RouteScout's SYN-ACK Attack Simulation

This Python script simulates SYN-ACK attacks with different modes, combining two attack scenarios. It generates SYN packets and their corresponding ACK responses and saves the attack traffic to a PCAP file.

### Usage

1. **Run the Script**

   - Execute the Python script `routescout-attack.py`:
     ```bash
     python routescout-attack.py
     ```

2. **Review Output**

   - The script will generate SYN packets and their corresponding ACK responses based on two attack modes, A1 and A2.
   - The attack traffic will be saved to a PCAP file named `pcap_file_to_save_attack_flows.pcap` in the same directory.

3. **Adjust Parameters (Optional)**

   - Modify the parameters such as `avg_delay`, `num_attack_flows`, `min_delay`, `max_delay`, and others in the script according to your requirements.
   - Adjust the logic for each attack mode as needed.

### Note

- This script combines two SYN-ACK attack scenarios, with mode A1 simulating one attack logic and mode A2 simulating another.
- Ensure you have sufficient permissions to create and write to the PCAP file in the specified directory.
- For more details, follow Section III of our [paper](link)