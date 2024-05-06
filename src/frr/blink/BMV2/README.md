# Normal Experiment
## To run the P4 code and setup the topology
sudo p4run --config topologies/5switches.json

## Run the following commands to start the end hosts h1(client) and h2(server) on separate terminals
* mx h1
* mx h2

## To run the blink controller and P4 controller on separate terminals
* sudo python -m controller.blink_controller --port 10000 --log_dir log --log_level 20 --routing_file topologies/5switches_routing.json --threshold 31 --topo_db topology.db
* sudo python -m controller.run_p4_controllers --topo_db topology.db --controller_ip localhost --controller_port 10000 --routing_file topologies/5switches_routing.json

## Traffic generation
### On h2, run the following commands to start the server code
* ulimit -n 1000000
* python -m traffic_generation.run_servers --ports 11000,14000 --log_dir log_traffic

### On h1. run the following commands to start the client code
#### Total 3000 flows, therefore 3000 TCP ports are opened
#### Bandwidth is 85 MBps
#### Flow rate is 20 flows per sec
* ulimit -n 1000000
* python -m traffic_generation_attack.run_clients --dst_ip 10.0.5.2 --src_ports 11000,14000  --dst_ports 11000,14000 --ipd 0  --duration 150 --bw 85 --flow_rate 20 --flow_count 3000

## Simulating a failure
sudo ifconfig s1-eth2 down
apt-get install speedometer
speedometer -t s1-eth1
speedometer -t s1-eth2
speedometer -t s1-eth3

## To induce 10% loss in link s1-eth2
sudo tc qdisc replace dev s1-eth2 root netem loss 10%

## To check the register values from CP
simple_switch_CLI --thrift-port 9090
Then to read --> register_read "name of the register"

# Attack Experiment:

## Drop reset packet on h1  
Since we use scapy to generate TCP packets, linux kernel/socket has no idea about the TCP seq and ack numbers, hence sends a RST packet instead. We have to make sure that this packet is not seen
* iptables -L -n
* iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 10.0.1.1 -d 10.0.5.2 -j DROP

## Traffic generation
### On h2, run the following commands to start the server code
* ulimit -n 1000000
* python -m traffic_generation.run_servers --ports 11000,14000 --log_dir log_traffic

### On h1. run the following commands to start the client code
#### Total 3000 normal flows, and 150 attack flows -> we are not actually establishing connection with end host h2 for attack flows
#### Bandwidth is 85 MBps
#### Flow rate is 20 flows per sec
* ulimit -n 1000000
* python -m traffic_generation_attack.run_clients_final --dst_ip 10.0.5.2 --src_ports 11000,14000  --dst_ports 11000,14000 --ipd 0  --duration 150 --bw 85 --flow_rate 20 --flow_count 3000

# Get the features from control plane after every 5 secs

## Flow size, flow duration and flow id
* Command to get the features flow duration is present command1.txt
* Command to get the features flow size is present command2.txt
* Command to get the features flow id is present command3.txt

## Run on a separate terminal to download all these three features into a csv file
python3 register_read from CP/register.py












