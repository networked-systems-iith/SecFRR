import sys
import os
import socket
import select
import errno
import logging
import logging.handlers
import threading
import argparse
import time
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from p4utils.utils.sswitch_p4runtime_API import SimpleSwitchP4RuntimeAPI
import json

from util import logger
from util import sched_timer

class HiddenPrints:
    def __enter__(self):
        self._original_stdout = sys.stdout  #used to display the o/p on the screen
        sys.stdout = open(os.devnull, 'w')   #redirects the standard output to a file

    def __exit__(self, exc_type, exc_val, exc_tb):
        sys.stdout.close()                     #close the standard output
        sys.stdout = self._original_stdout

class BlinkController:

    def __init__(self, topo_db, sw_name, ip_controller, port_controller, log_dir, \
       monitoring=True, routing_file=None):   #defining a constructor for the BlinkController class

       #code to load the topology and set the controller and log directory

        self.topo = load_topo('topology.json')
        #self.controller={}
        self.sw_name = sw_name
        
        self.thrift_port = self.topo.get_thrift_port(sw_name)#retrieves the p4switch port number
        self.cpu_port = self.topo.get_cpu_port_index(self.sw_name)
        #self.connect_to_switches()
        self.controller = SimpleSwitchThriftAPI(self.thrift_port)
        

        # self.controller=SimpleSwitchP4RuntimeAPI(self.topo[self.sw_name]['device_id'],
        #                                         self.topo[self.sw_name]['grpc_port'],
        #                                         p4rt_path=self.topo[self.sw_name]['p4rt_path'],
        #                                         json_path=self.topo[self.sw_name]['json_path'])

        
        #self.connect_to_switches()
        self.controller.reset_state()
        #self.connect_to_switches()
        self.log_dir = log_dir
        #device_id=self.topo.get_p4switch_id(self.sw_name)  #get the id of the p4 switch
        #grpc_port=self.topo.get_grpc_port(self.sw_name)  #get the grpc port
        #dictionary=dict( for subString in s.split(":"))
       
    # # def __init__(self):
    #     self.topo=load_topo('topology.json')
    #     for p4switch in self.topo.get_p4switches():
    #         self.thrift_port=self.topo.get_thrift_port(p4switch)
    #         self.cpu_port=self.topo.get_cpu_port_index(p4switch)
    #         self.controller={}
    #         self.controller[p4switch]=SimpleSwitchThriftAPI(self.thrift_port)
    #         self.controller.reset_state()
    #         self.log_dir=log_dir


        print('connecting to ', ip_controller, port_controller)
        # Socket used to communicate with the controller
        #socket code to connect switch and controller
        self.sock_controller = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (ip_controller, port_controller)
        self.sock_controller.connect(server_address)
        print ('Connected!')

        # Send the switch name to the controller
        #send the switch name to the controller via socket
        self.sock_controller.sendall(sw_name.encode())
        #self.sock_controller.sendall(str(sw_name))

        self.make_logging()  #enables logging for this file 

        if monitoring:
            # Monitoring scheduler
            self.t_sched = sched_timer.RepeatingTimer(10, 0.5, self.scheduling)
            self.t_sched.start()

        self.mapping_dic = {}  #creates a list
        tmp = list(self.topo.get_hosts())+list(self.topo.get_p4switches()) # list of hosts and switches in the topology
        self.mapping_dic = {k: v for v, k in enumerate(tmp)} #o/p {0:h1 ,1:h2 ,2:s1,,,}
        self.log.info(str(self.mapping_dic))  #to confirm that all switches and hosts are working well

        self.routing_file = routing_file
        print ('routing_file ', routing_file)
        if self.routing_file is not None:
            json_data = open(self.routing_file)
            self.topo_routing = json.load(json_data) #takes the file object and returns the json object in key value pair

    # def connect_to_switches(self):
    #     for p4rtswitch, data in self.topo.get_p4switches().items():
    #         device_id = self.topo.get_p4switch_id(p4rtswitch)
    #         grpc_port = self.topo.get_grpc_port(p4rtswitch)
    #         p4rt_path = data['p4rt_path']
    #         json_path = data['json_path']
    #         self.controller[p4rtswitch] = SimpleSwitchP4RuntimeAPI(device_id, grpc_port,
    #                                                                 p4rt_path=p4rt_path,
    #                                                                 json_path=json_path)
    def make_logging(self):
        # Logger for the pipeline
        logger.setup_logger('p4_to_controller', self.log_dir+'/p4_to_controller_'+ \
            str(self.sw_name)+'.log', level=logging.INFO)
        self.log = logging.getLogger('p4_to_controller')

        # Logger for the sliding window
        logger.setup_logger('p4_to_controller_sw', self.log_dir+'/p4_to_controller_'+ \
            str(self.sw_name)+'_sw.log', level=logging.INFO)
        self.log_sw = logging.getLogger('p4_to_controller_sw')

        # Logger for the rerouting
        logger.setup_logger('p4_to_controller_rerouting', self.log_dir+'/p4_to_controller_'+ \
            str(self.sw_name)+'_rerouting.log', level=logging.INFO)
        self.log_rerouting = logging.getLogger('p4_to_controller_rerouting')

        # Logger for the Flow Selector
        logger.setup_logger('p4_to_controller_fs', self.log_dir+'/p4_to_controller_'+ \
            str(self.sw_name)+'_fs.log', level=logging.INFO)
        self.log_fs = logging.getLogger('p4_to_controller_fs')

    def scheduling(self): #this is schrduling for log how frequently and what needs to be printed on log files for every host

        for host in list(self.topo.get_hosts()):
            prefix = self.topo.get_host_ip(host)+'/24'

            # Print log about the sliding window
            for id_prefix in [self.mapping_dic[host]*2, self.mapping_dic[host]*2+1]:

                with HiddenPrints():
                    sw_time = float(self.controller.register_read('sw_time', index=id_prefix))/1000.
                    sw_index = self.controller.register_read('sw_index', index=id_prefix)
                    sw_sum = self.controller.register_read('sw_sum', index=id_prefix)
                self.log_sw.info('sw_time\t'+host+'\t'+prefix+'\t'+str(id_prefix)+'\t'+str(sw_time))
                self.log_sw.info('sw_index\t'+host+'\t'+prefix+'\t'+str(id_prefix)+'\t'+str(sw_index))

                if sw_sum >= 32:
                    self.log_sw.info('sw_sum\t'+host+'\t'+prefix+'\t'+str(id_prefix)+'\t'+str(sw_sum)+'\tREROUTING')
                else:
                    self.log_sw.info('sw_sum\t'+host+'\t'+prefix+'\t'+str(id_prefix)+'\t'+str(sw_sum))


                sw = []
                tmp = 'sw '+host+' '+prefix+' '+str(id_prefix)+'\t'
                for i in range(0, 10):
                    with HiddenPrints():
                        binvalue = int(self.controller.register_read('sw', (id_prefix*10)+i))
                    tmp = tmp+str(binvalue)+','
                    sw.append(binvalue)
                tmp = tmp[:-1]
                self.log_sw.info(str(tmp))

        # Print log about rerouting
        for host in list(self.topo.get_hosts()):
            prefix = self.topo.get_host_ip(host)+'/24'

            for id_prefix in [self.mapping_dic[host]*2, self.mapping_dic[host]*2+1]:

                with HiddenPrints():
                    nh_avaibility_1 = self.controller.register_read('nh_avaibility_1', index=id_prefix)
                    nh_avaibility_2 = self.controller.register_read('nh_avaibility_2', index=id_prefix)
                    nh_avaibility_3 = self.controller.register_read('nh_avaibility_3', index=id_prefix)
                    nbflows_progressing_2 = self.controller.register_read('nbflows_progressing_2', index=id_prefix)
                    nbflows_progressing_3 = self.controller.register_read('nbflows_progressing_3', index=id_prefix)
                    rerouting_ts = self.controller.register_read('rerouting_ts', index=id_prefix)
                    threshold = self.controller.register_read('threshold_registers', index=id_prefix)

                self.log_rerouting.info('nh_avaibility\t'+host+'\t'+prefix+'\t'+ \
                str(id_prefix)+'\t'+str(nh_avaibility_1)+'\t'+ \
                str(nh_avaibility_2)+'\t'+str(nh_avaibility_3))
                self.log_rerouting.info('nblows_progressing\t'+host+'\t'+prefix+'\t'+ \
                str(id_prefix)+'\t'+str(nbflows_progressing_2)+'\t'+ \
                str(nbflows_progressing_3))
                self.log_rerouting.info('rerouting_ts\t'+host+'\t'+prefix+'\t'+ \
                str(id_prefix)+'\t'+str(rerouting_ts))
                self.log_rerouting.info('threshold\t'+host+'\t'+prefix+'\t'+ \
                str(id_prefix)+'\t'+str(threshold))

                nexthop_str = ''
                nha = [nh_avaibility_1, nh_avaibility_2, nh_avaibility_3]
                i = 0
                if self.routing_file is not None:
                    bgp_type = 'customer' if id_prefix%2 == 0 else 'customer_provider_peer'
                    if bgp_type not in self.topo_routing['switches'][self.sw_name]['prefixes'][host]:
                        nexthop_str = 'NoPathAvailable'
                    else:
                        if len(self.topo_routing['switches'][self.sw_name]['prefixes'][host][bgp_type]) == 2:
                            self.topo_routing['switches'][self.sw_name]['prefixes'][host][bgp_type].append(self.topo_routing['switches'][self.sw_name]['prefixes'][host][bgp_type][-1])
                        for nexthop in self.topo_routing['switches'][self.sw_name]['prefixes'][host][bgp_type]:
                            tmp = 'y' if nha[i] == 0 else 'n'
                            nexthop_str = nexthop_str+str(nexthop)+'('+tmp+')\t'
                            i += 1
                        nexthop_str = nexthop_str[:-1]
                self.log_rerouting.info('nexthop\t'+host+'\t'+prefix+'\t'+ \
                str(id_prefix)+'\t'+str(nexthop_str))

        # Print log about the flow selector
        for host in list(self.topo.get_hosts()):
            prefix = self.topo.get_host_ip(host)+'/24'

            for id_prefix in [self.mapping_dic[host]*2, self.mapping_dic[host]*2+1]:

                sw = []
                tmp = 'fs_key '+host+' '+prefix+' '+str(id_prefix)+'\t'
                for i in range(0, 64):
                    with HiddenPrints():
                        binvalue = int(self.controller.register_read('flowselector_key', 64*id_prefix+i))
                    tmp = tmp+str(binvalue)+','
                    sw.append(binvalue)
                tmp = tmp[:-1]
                self.log_fs.info(str(tmp))

                sw = []
                tmp = 'fs '+host+' '+prefix+' '+str(id_prefix)+'\t'
                for i in range(0, 64):
                    with HiddenPrints():
                        binvalue = int(self.controller.register_read('flowselector_ts', 64*id_prefix+i))
                    tmp = tmp+str(binvalue)+','
                    sw.append(binvalue)
                tmp = tmp[:-1]
                self.log_fs.info(str(tmp))

                sw = []
                tmp = 'fs_last_ret '+host+' '+prefix+' '+str(id_prefix)+'\t'
                for i in range(0, 64):
                    with HiddenPrints():
                        binvalue = int(self.controller.register_read('flowselector_last_ret', 64*id_prefix+i))
                    tmp = tmp+str(binvalue)+','
                    sw.append(binvalue)
                tmp = tmp[:-1]
                self.log_fs.info(str(tmp))

                sw = []
                tmp = 'fs_last_ret_bin '+host+' '+prefix+' '+str(id_prefix)+'\t'
                for i in range(0, 64):
                    with HiddenPrints():
                        binvalue = int(self.controller.register_read('flowselector_last_ret_bin', 64*id_prefix+i))
                    tmp = tmp+str(binvalue)+','
                    sw.append(binvalue)
                tmp = tmp[:-1]
                self.log_fs.info(str(tmp))

                sw = []
                tmp = 'fs_fwloops '+host+' '+prefix+' '+str(id_prefix)+'\t'
                for i in range(0, 64):
                    with HiddenPrints():
                        binvalue = int(self.controller.register_read('flowselector_fwloops', 64*id_prefix+i))
                    tmp = tmp+str(binvalue)+','
                    sw.append(binvalue)
                tmp = tmp[:-1]
                self.log_fs.info(str(tmp))

                sw = []
                tmp = 'fs_correctness '+host+' '+prefix+' '+str(id_prefix)+'\t'
                for i in range(0, 64):
                    with HiddenPrints():
                        binvalue = int(self.controller.register_read('flowselector_correctness', 64*id_prefix+i))
                    tmp = tmp+str(binvalue)+','
                    sw.append(binvalue)
                tmp = tmp[:-1]
                self.log_fs.info(str(tmp))

    #main method which is used to set the next hop table in p4 program
    def forwarding(self):

        print("***********call forwarding**************")
        p4switches = self.topo.get_p4switches() #set of switches along with their properties
        interfaces_to_node=self.topo.get_interfaces_to_node(self.sw_name) #gets dictionary that

        print('\n')
        #print(interfaces_to_node)
        #associates every nodes interfaces to the connected neighbor.
        #interfaces_to_node = p4switches[self.sw_name]['interfaces_to_node']  #for that particular switch get the interface from the set
        #this will be in the form of key value pairs
        for k, v in interfaces_to_node.items():

            # try:

            #     #retrieves all the host and their configuration params in that we are selecting mac address
            #     dst_mac =self.topo.get_hosts()[v][self.sw_name]['mac'] 
            # except KeyError:
            #     dst_mac = self.topo.get_p4switches()[v][self.sw_name]['mac']
            # try:
            #     dst_mac =self.topo.get_hosts()[v][self.sw_name]['mac'] 
            # except KeyError:
            #     dst_mac = self.topo.get_p4switches()[v][self.sw_name]['mac']
            dst_mac=self.topo.node_to_node_mac(v,self.sw_name)
            src_mac=self.topo.node_to_node_mac(self.sw_name,v)

            #get the mac address for the switch
            #src_mac = p4switches[self.sw_name][v]['mac']
            #get the interface for that particular switch
            #outport = p4switches[self.sw_name]['interfaces_to_port'][p4switches[self.sw_name][v]['intf']]
            outport=self.topo.node_to_node_port_num(sw_name,v)
            #self.log.info('table add send set_nh '+str(self.mapping_dic[v])+' => '+str(outport)+' '+str(src_mac)+' '+str(dst_mac))
            self.log.info('table add send set_nh '+str(v)+' => '+str(outport)+' '+str(src_mac)+' '+str(dst_mac))
            #adding the entries to the table
            #send is the table with set_nh as the action which sets output port,source mac,destination mac
            self.controller.table_add('send', 'set_nh', [str(self.mapping_dic[v])], [str(outport), str(src_mac), str(dst_mac)])

    #it will take the necessary action based on the given request
    def run(self):
        print("***********call running**************")

        sock_list = [self.sock_controller] # this is the socket created above for every switch
        controller_data = ''

        while True:
            inready, outready, excepready = select.select (sock_list, [], [])

            for sock in inready:
                if sock == self.sock_controller:
                    data_tmp = ''
                    toreturn = None

                    try:
                        data_tmp = sock.recv(100000000)  #this is received from blink_controller
                        data_tmp.decode()
                    except socket.error as e:
                        err = e.args[0]
                        if not (err == errno.EAGAIN or err == errno.EWOULDBLOCK):
                            print ('p4_to_controller: ', e)
                            sock.close()
                            sock = None

                    data_tmp=data_tmp.decode("utf-8")

                    if len(data_tmp) > 0:
                        controller_data += data_tmp

                        next_data = ''
                        while len(controller_data) > 0 and controller_data[-1] != '\n':
                            next_data = controller_data[-1]+next_data
                            controller_data = controller_data[:-1]

                        
                        print('\n')
                        print("controller data : ")
                        print(controller_data)

                        toreturn = controller_data
                        controller_data = next_data
                    
                    if toreturn is not None:
                        for line in toreturn.split('\n'):
                            #add to the necessary tables 
                            if line.startswith('table add '):
                                line = line.rstrip('\n').replace('table add ', '')

                                fwtable_name = line.split(' ')[0]
                                action_name = line.split(' ')[1]

                                match_list = line.split(' => ')[0].split(' ')[2:]
                                action_list = line.split(' => ')[1].split(' ')

                                #print (line)
                                #print (fwtable_name, action_name, match_list, action_list)

                                self.log.info(line)
                                self.controller.table_add(fwtable_name, action_name, \
                                    match_list, action_list)
                            #do the necessary register writes
                            if line.startswith('do_register_write'):
                                line = line.rstrip('\n')
                                linetab = line.split(' ')

                                register_name = linetab[1]
                                index = int(linetab[2])
                                value = int(linetab[3])

                                self.log.info(line)
                                self.controller.register_write(register_name, \
                                    index, value)


                            #resets the state of all registers
                            if line.startswith('reset_states'):
                                self.log.info('RESETTING_STATES')

                                # First stop the scheduler to avoid concurrent used
                                # of the Thirft server

                                #before restting copy the register value to the file

                                self.t_sched.cancel()
                                while self.t_sched.running: # Wait the end of the log printing
                                    time.sleep(0.5)

                                time.sleep(1)


                                # Reset the state of the switch
                                self.controller.register_reset('nh_avaibility_1')
                                self.controller.register_reset('nh_avaibility_2')
                                self.controller.register_reset('nh_avaibility_3')
                                self.controller.register_reset('nbflows_progressing_2')
                                self.controller.register_reset('nbflows_progressing_3')
                                self.controller.register_reset('rerouting_ts')
                                #print the timestamp value before that
                                
                                self.controller.register_reset('timestamp_reference')
                                self.controller.register_reset('sw_time')
                                self.controller.register_reset('sw_index')
                                self.controller.register_reset('sw_sum')
                                self.controller.register_reset('sw')
                                self.controller.register_reset('flowselector_key')
                                self.controller.register_reset('flowselector_nep')
                                self.controller.register_reset('flowselector_ts')
                                self.controller.register_reset('flowselector_last_ret')
                                self.controller.register_reset('flowselector_last_ret_bin')
                                self.controller.register_reset('flowselector_correctness')
                                self.controller.register_reset('flowselector_fwloops')
                                self.controller.register_reset('start_time')
                                self.controller.register_reset('end_time')
                                self.controller.register_reset('dump_array')


                                print (self.sw_name, ' RESET.')

                                # Restart the scheduler
                                time.sleep(1)
                                self.t_sched.start()

#this is the main program
if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('--topo_db', nargs='?', type=str, default=None, help='Topology database.')
    parser.add_argument('--sw_name', nargs='?', type=str, default=None, help='Name of the P4 switch.')
    #parser.add_argument('--switch',nargs='?', type=dict, default=None, help='Name of the P4 switch.')
    parser.add_argument('--controller_ip', nargs='?', type=str, default='localhost', help='IP of the controller (Default is localhost)')
    parser.add_argument('--controller_port', nargs='?', type=int, default=None, help='Port of the controller')
    parser.add_argument('--log_dir', nargs='?', type=str, default='log', help='Directory used for the log')
    parser.add_argument('--routing_file', nargs='?', type=str, default=None, help='File (json) with the routing')

    args = parser.parse_args()
    topo_db = args.topo_db
    sw_name = args.sw_name
    #switch=args.switch
    ip_controller = args.controller_ip
    port_controller = args.controller_port
    log_dir = args.log_dir
    routing_file = args.routing_file

    controller = BlinkController(topo_db, sw_name, ip_controller, port_controller, \
    log_dir, routing_file=routing_file)

    controller.forwarding()
    controller.run()
