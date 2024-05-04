Important commands: 
1) simple_switch_CLI --thrift-port 9090
	"register_read dump_array"
2) sudo p4run --config topologies/5switches.json
3) sudo python -m controller.run_p4_controllers --topo_db topology.db --controller_ip localhost --controller_port 10000 --routing_file topologies/5switches_routing.json
4) sudo python -m controller.blink_controller --port 10000 --log_dir log --log_level 20 --routing_file topologies/5switches_routing.json --threshold 31 --topo_db topology.db
5) watch -n1 'ifconfig s1-eth1| tee -a s1-eth1.log'
6) watch -n1 'ifconfig s1-eth2| tee -a s1-eth2.log'
7) watch -n1 'ifconfig s1-eth3| tee -a s1-eth3.log'
8) sudo tcpdump -i s1-eth1 -w outfile-%s -G 1 (Link: https://superuser.com/questions/297521/how-to-capture-last-n-seconds-of-packets-using-tcpdump)
9) ulimit -n 1000000 [Increase number of files can be opened in parallel]
10) Bytes recieved at an interface: cat /sys/class/net/s1-eth1/statistics/rx_bytes

1) Fixing parameters:
	Bandwidth per link: 70Mbps
	Bandwidth which every flow gets = 
	No. of flows: 2000
	Flows per second: 20 flows/sec
	Flows will be sent for 2000/20 = 100sec




sudo p4run --config topologies/5switches.json
sudo python -m controller.blink_controller --port 10000 --log_dir log --log_level 20 --routing_file topologies/5switches_routing.json --threshold 31 --topo_db topology.db
sudo python -m controller.run_p4_controllers --topo_db topology.db --controller_ip localhost --controller_port 10000 --routing_file topologies/5switches_routing.json



python -m traffic_generation_normal.run_servers --ports 11000,16000

python -m traffic_generation_normal.run_clients --dst_ip 10.0.5.2 --src_ports 11000,16000  --dst_ports 11000,16000 --ipd 0  --duration 100 --bw 40 --flow_rate 20 --flow_count 5000

#######################################################################################################################################
python -m traffic_generation_normal.run_clients --dst_ip 10.0.5.2 --src_ports 11000,16000  --dst_ports 11000,16000 --ipd 0  --duration 100 --bw 50 --flow_rate 20 --flow_count 5000