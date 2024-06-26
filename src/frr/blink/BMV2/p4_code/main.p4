#include <core.p4>
#include <v1model.p4>

#include "includes/headers.p4"
#include "includes/metadata.p4"
#include "includes/parser.p4"
#include "includes/macros.p4"

#include "pipeline/flowselector.p4"


control ingress(inout Parsed_packet pp,
                inout custom_metadata_t custom_metadata,
                inout standard_metadata_t standard_metadata) {

    /** Registers used by the Flow Selector **/
    register<bit<32>>(MAX_NB_PREFIXES*FLOWSELECTOR_NBFLOWS) flowselector_key;
    register<bit<32>>(MAX_NB_PREFIXES*FLOWSELECTOR_NBFLOWS) flowselector_nep;
    register<bit<9>>(MAX_NB_PREFIXES*FLOWSELECTOR_NBFLOWS) flowselector_ts;
    register<bit<16>>(MAX_NB_PREFIXES*FLOWSELECTOR_NBFLOWS) dst_port;
    register<bit<19>>(MAX_NB_PREFIXES*FLOWSELECTOR_NBFLOWS) flowselector_last_ret;
    register<bit<4>>(MAX_NB_PREFIXES*FLOWSELECTOR_NBFLOWS) flowselector_last_ret_bin;
    register<bit<1>>(MAX_NB_PREFIXES*FLOWSELECTOR_NBFLOWS) flowselector_correctness;
    register<bit<2>>(MAX_NB_PREFIXES*FLOWSELECTOR_NBFLOWS) flowselector_fwloops;


    
    /** Registers used by the sliding window **/
    register<bit<6>>(MAX_NB_PREFIXES*(bit<32>)(SW_NB_BINS)) sw;
    register<bit<19>>(MAX_NB_PREFIXES) sw_time;
    register<bit<4>>(MAX_NB_PREFIXES) sw_index;
    register<bit<6>>(MAX_NB_PREFIXES) sw_sum;

    // Register to store the threshold for each prefix (by default all the prefixes
    // have the same threshold, so this could just be a macro)
    register<bit<6>>(MAX_NB_PREFIXES) threshold_registers;

    // List of next-hops for each prefix
    register<bit<32>>(MAX_NB_PREFIXES*3) next_hops_port;

    // Register used to indicate whether a next-hop is working or not.
    register<bit<1>>(MAX_NB_PREFIXES) nh_avaibility_1;
    register<bit<1>>(MAX_NB_PREFIXES) nh_avaibility_2;
    register<bit<1>>(MAX_NB_PREFIXES) nh_avaibility_3;

    // Register use to keep track for each flow, the number of flows that restart
    // after the rerouting. One per backup next-hop
    register<bit<6>>(MAX_NB_PREFIXES) nbflows_progressing_2;
    register<bit<6>>(MAX_NB_PREFIXES) nbflows_progressing_3;

    // Timestamp of the rerouting
    register<bit<19>>(MAX_NB_PREFIXES) rerouting_ts;

    //registers to show the flow duration
    register<bit<19>>(MAX_NB_PREFIXES*FLOWSELECTOR_NBFLOWS) start_time;
    register <bit<19>>(MAX_NB_PREFIXES*FLOWSELECTOR_NBFLOWS) end_time;
    register <bit<9>>(6000) flow_duration_normal; // Eviction flow duration array
    register <bit<32>>(6000) packet_count_normal;
    register <bit<32>> (1) offset; // offset used as a pointer to eviction arrays 

    // Approach 2 for flow duration --> Threshold crosses 32, take a snapshot of the network stats
    register<bit<19>>(MAX_NB_PREFIXES*FLOWSELECTOR_NBFLOWS) flow_duration;
    register<bit<32>>(1) reroute_bit; // As of now, only 1 prefix, make 1 as MAX_NB_PREFIX later!!If bit=0, reroute never occured
    register<bit<19>>(1) reroute_time;
    register<bit<19>>(1) start;

    // Approach 2 for flow size --> Threshold crosses 32, take a snapshot of the network stats
    register<bit<32>>(MAX_NB_PREFIXES*FLOWSELECTOR_NBFLOWS) flow_size;
    
    // Approach 2 for retrieving the index of attack flows --> Threshold crosses 32, take a snapshot of the network stats, replica of flowselector_key 
    register<bit<32>>(MAX_NB_PREFIXES*FLOWSELECTOR_NBFLOWS) flowselector_key_attack_index;
    register<bit<19>>(MAX_NB_PREFIXES*FLOWSELECTOR_NBFLOWS) flowselector_ts_fd;

    //registers to show flow size
    register<bit<32>>(MAX_NB_PREFIXES*FLOWSELECTOR_NBFLOWS) selected_flow_size;
    register <bit<32>>(6000) flow_size_normal; // Eviction flow size array
	
    //register which stores the value of all registers 
    register<bit<9>>(3*MAX_NB_PREFIXES*FLOWSELECTOR_NBFLOWS) dump_array; 
    register<bit<32>>(3*MAX_NB_PREFIXES*FLOWSELECTOR_NBFLOWS) dump_fc;

    // Every time period seconds (define by MAX_FLOWS_SELECTION_TIME), the
    // controller updates this register
    register<bit<48>>(32w1) timestamp_reference;

    // Switch IP used to reply to the traceroutes
    register<bit<32>>(32w1) switch_ip;

    //register to update the offset
    //register<bit<32>>(MAX_NB_PREFIXES) offset;

   //// register<bit<32>>(MAX_NB_PREFIXES) sample;
    register<bit<32>>(32w1) s;


    //register<bit<32>>(32w100) dst_reg;

    // registers for attack traffic
    register<bit<32>>(150) attack_nep;
    register<bit<32>>(150) attack_ret;
    bit<32> attack_key;    
    bit<32> current_attack_nep;
    bit<32> current_attack_ret;

    bit<9> ts_second;

    bit<48> ts_tmp;
    bit<6> sum_tmp;
    bit<6> threshold_tmp;
    bit<6> correctness_tmp;
    bit<19> rerouting_ts_tmp;
    bit<2> flowselector_fwloops_tmp;
    bit<1> nh_avaibility_1_tmp;
    bit<1> nh_avaibility_2_tmp;
    bit<1> nh_avaibility_3_tmp;

    flowselector() fc;

    bit<32> threshold_check;

    register<bit<32>>(1024) reg_bl_code;

    register<bit<32>>(1024) bl_count;

    bit<32> collision_check;

    bit<32> temp_count;
    /**
    * Mark packet to drop
    */
    action _drop() {
        mark_to_drop(standard_metadata);
    }

    /**
    * Set the metadata used in the normal pipeline
    */
    action set_meta(bit<32> id, bit<1> use_blink, bit<32> default_nexthop_port) {
        custom_metadata.id = id;
        custom_metadata.use_blink = use_blink;
        custom_metadata.next_hop_port = default_nexthop_port;
    }

    table meta_fwtable {
        actions = {
            set_meta;
            _drop;
        }
        key = {
            pp.ipv4.dstAddr: lpm;
            custom_metadata.bgp_ngh_type: exact;
        }
        size = 20000;
        default_action = _drop;
    }
    /**
    * Set the metadata about BGP (provider, peer or customer)
    */
    action set_bgp_tag(bit<2> neighbor_bgp_type) {
        custom_metadata.bgp_ngh_type = neighbor_bgp_type;
    }

    table bgp_tag {
        actions = {
            set_bgp_tag;
            NoAction;
        }
        key = {
            standard_metadata.ingress_port: exact;
            pp.ethernet.srcAddr: exact;
        }
        size = 20000;
        default_action = NoAction; // By default bgp_ngh_type will be 0, meaning customer (used for the host)
    }

    /**
    * Set output port and destination MAC address based on port ID
    */
    action set_nh(bit<9> port, EthernetAddress smac, EthernetAddress dmac) {
        standard_metadata.egress_spec = port;
        pp.ethernet.srcAddr = smac;
        pp.ethernet.dstAddr = dmac;

        // Decrement the TTL by one
        pp.ipv4.ttl = pp.ipv4.ttl - 1;
    }

    table send {
        actions = {
            set_nh;
            _drop;
        }
        key = {
            custom_metadata.next_hop_port: exact;
        }
        size = 1024;
        default_action = _drop;
    }

    
    apply
    {
        //dst_reg.write((bit<32>)pp.tcp.dstPort,pp.tcp.dstPort);

        timestamp_reference.read(ts_tmp, 32w0);

        // If the difference between the reference timestamp and the current
        // timestamp is above MAX_FLOWS_SELECTION_TIME, then reference timestamp
        // is updated
        if (standard_metadata.ingress_global_timestamp - ts_tmp > MAX_FLOWS_SELECTION_TIME)
        {
            timestamp_reference.write(32w0, standard_metadata.ingress_global_timestamp);
        }

        timestamp_reference.read(ts_tmp, 32w0);

        custom_metadata.ingress_timestamp_second =
            (bit<9>)((standard_metadata.ingress_global_timestamp - ts_tmp) >> 20);
        custom_metadata.ingress_timestamp_millisecond =
            (bit<19>)((standard_metadata.ingress_global_timestamp - ts_tmp) >> 10);

        bgp_tag.apply();
        meta_fwtable.apply();
      

        //Traceroute Logic (only for TCP probes)
        if (pp.ipv4.isValid() && pp.tcp.isValid() && pp.ipv4.ttl == 1){
           /* Code for attack flow  
	    bit<16> attack_key_temp;
            attack_key_temp = pp.tcp.srcPort - 11000;
	    attack_key = ((bit<32>)attack_key_temp);
            attack_nep.read(current_attack_nep, attack_key);
	    attack_ret.read(current_attack_ret, attack_key);
            if(current_attack_nep == 32w0 && current_attack_ret == 0) // It is the first packet 
	    {
		attack_nep.write(attack_key, pp.tcp.seqNo + (bit<32>)custom_metadata.tcp_payload_len);
		attack_ret.write(attack_key, 32w1);
                pp.ipv4.ttl = 0;
                
             }
	    else if ((current_attack_nep == pp.tcp.seqNo + (bit<32>)custom_metadata.tcp_payload_len) && (current_attack_ret == 1))
{
    pp.ipv4.ttl = 64;
    attack_nep.write(attack_key, 32w0);
    attack_ret.write(attack_key, 32w0);
}

*/


// ICMP message if ttl = 1
	    // Set new headers valid
            pp.ipv4_icmp.setValid();
            pp.icmp.setValid();

            // Set egress port == ingress port
            standard_metadata.egress_spec = standard_metadata.ingress_port;

            //Ethernet: Swap map addresses
            bit<48> tmp_mac = pp.ethernet.srcAddr;
            pp.ethernet.srcAddr = pp.ethernet.dstAddr;
            pp.ethernet.dstAddr = tmp_mac;

            //Building new Ipv4 header for the ICMP packet
            //Copy original header (for simplicity)
            pp.ipv4_icmp = pp.ipv4;
            //Set destination address as traceroute originator
            pp.ipv4_icmp.dstAddr = pp.ipv4.srcAddr;
            //Set src IP to the IP assigned to the switch
            switch_ip.read(pp.ipv4_icmp.srcAddr, 0);

            //Set protocol to ICMP
            pp.ipv4_icmp.protocol = IP_ICMP_PROTO;
            //Set default TTL
            pp.ipv4_icmp.ttl = 64;
            //And IP Length to 56 bytes (normal IP header + ICMP + 8 bytes of data)
            pp.ipv4_icmp.totalLen= 56;

            //Create ICMP header with
            pp.icmp.type = ICMP_TTL_EXPIRED;
            pp.icmp.code = 0;

            //make sure all the packets are length 70.. so wireshark does not complain when tpc options,etc
            truncate((bit<32>)70);
      }
        else //if (pp.ipv4.ttl > 1)
        {
            // Get the threshold to use for fast rerouting (default is 32 flows)
            threshold_registers.read(threshold_tmp, custom_metadata.id);

            // If it is a TCP packet and destined to a destination that has Blink activated
            if (pp.tcp.isValid() && custom_metadata.use_blink == 1w1)
            {
                // If it is a SYN packet, then we set the tcp_payload_len to 1
                // (even if the packet actually does not have any payload)
                if (pp.tcp.syn == 1w1 || pp.tcp.fin == 1w1)
                    {
                    if (pp.tcp.srcPort == 11000)
                        start.write(0,custom_metadata.ingress_timestamp_millisecond);
                    custom_metadata.tcp_payload_len = 16w1;
                    }
                else
                    custom_metadata.tcp_payload_len = pp.ipv4.totalLen - (bit<16>)(pp.ipv4.ihl)*16w4 - (bit<16>)(pp.tcp.dataOffset)*16w4; // ip_len - ip_hdr_len - tcp_hdr_len

                if (custom_metadata.tcp_payload_len > 0)
                {
                    fc.apply(pp, custom_metadata, standard_metadata,
                        flowselector_key, flowselector_nep, flowselector_ts,
                        flowselector_last_ret, flowselector_last_ret_bin,
                        flowselector_correctness, flowselector_fwloops,
                        sw, sw_time, sw_index, sw_sum,
                        nbflows_progressing_2,
                        nbflows_progressing_3,
                        rerouting_ts,
                        start_time,
                        end_time,
                        flow_duration_normal,
			            packet_count_normal,
                        dump_array,
                        dump_fc,
                        dst_port,
                        offset,
                        flow_duration,
                        reroute_bit,
                        flow_size,
                        flowselector_key_attack_index,
                        flowselector_ts_fd,
			            selected_flow_size,
			            flow_size_normal,
                        s);
                    
                    
                    sw_sum.read(sum_tmp, custom_metadata.id);
                    nh_avaibility_1.read(nh_avaibility_1_tmp, custom_metadata.id);

                    // Trigger the fast reroute if sum_tmp is greater than the
                    // threshold (i.e., default 31)
                    if (sum_tmp > threshold_tmp && nh_avaibility_1_tmp == 0)
                    {
                        
                        bit<19> st;
                        bit<19> diff;
                        // Write 1, to deactivate this next-hop
                        // and start using the backup ones
                        nh_avaibility_1.write(custom_metadata.id, 1);
                        reroute_bit.write(0, 1); // Rerouting happened, so make reroute bit to 1 i.e. we don't need to consider any further stats
                        start.read(st,0);
                        diff = custom_metadata.ingress_timestamp_millisecond - st;
                        reroute_time.write(0, diff);
                        // Initialize the registers used to check flow progression
                        nbflows_progressing_2.write(custom_metadata.id, 6w0);
                        nbflows_progressing_3.write(custom_metadata.id, 6w0);

                        // Storing the timestamp of the rerouting
                        rerouting_ts.write(custom_metadata.id, custom_metadata.ingress_timestamp_millisecond);
                    }
                }
            }
            
            
            if (custom_metadata.use_blink == 1w1) // for every packet using blink
            {
                nh_avaibility_1.read(nh_avaibility_1_tmp, custom_metadata.id);
                nh_avaibility_2.read(nh_avaibility_2_tmp, custom_metadata.id);
                nh_avaibility_3.read(nh_avaibility_3_tmp, custom_metadata.id);
                rerouting_ts.read(rerouting_ts_tmp, custom_metadata.id);

                /*
                // All the selected flows, within the first second after the rerouting.
                if (custom_metadata.selected == 1w1 && rerouting_ts_tmp > 0 &&
                    (custom_metadata.ingress_timestamp_millisecond -
                    rerouting_ts_tmp) < ((bit<19>)TIMEOUT_PROGRESSION))
                {
                    // Monitoring the first backup NH
                    if (custom_metadata.flowselector_cellid < (FLOWSELECTOR_NBFLOWS >> 1))
                    {
                        // If the backup next-hop is working so far
                        if (nh_avaibility_2_tmp == 1w0)
                        {
                            next_hops_port.read(custom_metadata.next_hop_port, (custom_metadata.id//*3)+1);
                
                            if (custom_metadata.is_retransmission == 1w1) // If this is a retransmission
                            {
                                flowselector_fwloops.read(flowselector_fwloops_tmp,
                                    (FLOWSELECTOR_NBFLOWS * custom_metadata.id) + custom_metadata.flowselector_cellid);

                                // If a forwarding loop is detected for this flow
                                if (flowselector_fwloops_tmp == FWLOOPS_TRIGGER)
                                {
                                    // We switch to the third backup nexthop
                                    nh_avaibility_2.write(custom_metadata.id, 1);
                                    nh_avaibility_2_tmp = 1w1;
                                }
                                else
                                {
                                    flowselector_fwloops.write((FLOWSELECTOR_NBFLOWS * custom_metadata.id)
                                    + custom_metadata.flowselector_cellid, flowselector_fwloops_tmp + 1);
                                }
                            }
                        }
                        else
                        {
                            if (nh_avaibility_3_tmp == 1w0)
                            {
                                // Retrieve the port ID to use for that prefix
                                next_hops_port.read(custom_metadata.next_hop_port, (custom_metadata.id//*3)+2);
                            }
                            else
                            {
                                next_hops_port.read(custom_metadata.next_hop_port, (custom_metadata.id//*3)+0);
                            }
                        }

                    }
                    // Monitoring the second backup NH
                    else
                    {
                        // If the backup next-hop is working so far
                        if (nh_avaibility_3_tmp == 1w0)
                        {
                            next_hops_port.read(custom_metadata.next_hop_port, (custom_metadata.id//*3)+2);

                            if (custom_metadata.is_retransmission == 1w1) // If this is a retransmission
                            {
                                flowselector_fwloops.read(flowselector_fwloops_tmp,
                                    (FLOWSELECTOR_NBFLOWS * custom_metadata.id) + custom_metadata.flowselector_cellid);

                                // If a forwarding loop is detected for this flow
                                if (flowselector_fwloops_tmp == FWLOOPS_TRIGGER)
                                {
                                    // We switch to the third backup nexthop
                                    nh_avaibility_3.write(custom_metadata.id, 1);
                                    nh_avaibility_3_tmp = 1w1;
                                }
                                else
                                {
                                    flowselector_fwloops.write((FLOWSELECTOR_NBFLOWS * custom_metadata.id)
                                    + custom_metadata.flowselector_cellid, flowselector_fwloops_tmp + 1);
                                }
                            }
                        }
                        else
                        {
                            if (nh_avaibility_2_tmp == 1w0)
                            {
                                // Retrieve the port ID to use for that prefix
                                next_hops_port.read(custom_metadata.next_hop_port, (custom_metadata.id//*3)+1); // ADD THIS LINE
                            }
                            else
                            {
                                next_hops_port.read(custom_metadata.next_hop_port, (custom_metadata.id//*3)+0);
                            }
                        }
                    }
                }
                // Else: All the flows of the prefixes monitored by Blink
                else
                {
                    if (nh_avaibility_1_tmp == 1w0)
                    {
                        // Retrieve the port ID to use for that prefix
                        next_hops_port.read(custom_metadata.next_hop_port, (custom_metadata.id//*3)+0);
                    }
                    else if (nh_avaibility_2_tmp == 1w0)
                    {
                        next_hops_port.read(custom_metadata.next_hop_port, (custom_metadata.id//*3)+1);
                    }
                    else if (nh_avaibility_3_tmp == 1w0)
                    {
                        next_hops_port.read(custom_metadata.next_hop_port, (custom_metadata.id//*3)+2);
                    }
                    else
                    {
                        // If none of the backup next-hop is working, then we use primary next-hop
                        next_hops_port.read(custom_metadata.next_hop_port, (custom_metadata.id//*3)+0);
                    }
                }
                // Check if after one second at least more than half of the flows have
                // restarted otherwise deactive the corresponding next-hop
                if (rerouting_ts_tmp > 0 && (custom_metadata.ingress_timestamp_millisecond -
                    rerouting_ts_tmp) > ((bit<19>)TIMEOUT_PROGRESSION))
                {
                    nbflows_progressing_2.read(correctness_tmp, custom_metadata.id);
                    if (correctness_tmp < MIN_NB_PROGRESSING_FLOWS && nh_avaibility_2_tmp == 0)
                    {
                        nh_avaibility_2.write(custom_metadata.id, 1);
                    }

                    nbflows_progressing_3.read(correctness_tmp, custom_metadata.id);
                    if (correctness_tmp < MIN_NB_PROGRESSING_FLOWS && nh_avaibility_3_tmp == 0)
                    {
                        nh_avaibility_3.write(custom_metadata.id, 1);
                    }
                } */

            if (nh_avaibility_1_tmp == 1w1) // If primary path is 1. reroute traffic to next backup path, did for collection of the dataset
                    {
                        // Retrieve the port ID to use for that prefix
                        next_hops_port.read(custom_metadata.next_hop_port, (custom_metadata.id*3)+1);
                    }

            }

            // bit<32> modulo_value= 1023;
            // bit<8> index = (bit<32>)custom_metadata.BL&modulo_value;
            
            // reg_bl_code.read(collision_check,index);

            // bl_count.read(temp_count,index);
            // //probability of collision is 10^(-6) and we have only approx ~~ 10 distinct BL Values

            // if(temp_count==0 || custom_metadata.BL == collision_check)
            // {

            //     reg_bl_code.write(index,custom_metadata.BL);
        
            //     bl_count.read(temp_count,index);

            //     temp_count= temp_count + 1;

            //     bl_count.write(index,temp_count);

            // }
            // else
            // {   // linear probing one iteration.
            //     if(temp_count==0)
            //     {
            //     	// 
            //         index= ((custom_metadata.BL + 1)&modulo_value);

            //         reg_bl_code.write(index,custom_metadata.BL);

            //         bl_count.read(temp_count,index);

            //         temp_count= temp_count + 1;

            //         bl_count.write(index,temp_count);
            //     }

            // }

            send.apply();
        }
    }
}


/* ------------------------------------------------------------------------- */
control egress(inout Parsed_packet pp,
               inout custom_metadata_t custom_metadata,
               inout standard_metadata_t standard_metadata) {

   apply { }
}

/* ------------------------------------------------------------------------- */
control verifyChecksum(inout Parsed_packet pp, inout custom_metadata_t meta) {
    apply {
    }
}

/* ------------------------------------------------------------------------- */
control computeChecksum(inout Parsed_packet pp, inout custom_metadata_t meta) {
    apply {
    	update_checksum(
    	    pp.ipv4.isValid(),
                { pp.ipv4.version,
    	          pp.ipv4.ihl,
                  pp.ipv4.dscp,
                  pp.ipv4.ecn,
                  pp.ipv4.totalLen,
                  pp.ipv4.identification,
                  pp.ipv4.flags,
                  pp.ipv4.fragOffset,
                  pp.ipv4.ttl,
                  pp.ipv4.protocol,
                  pp.ipv4.srcAddr,
                  pp.ipv4.dstAddr },
                  pp.ipv4.hdrChecksum,
                  HashAlgorithm.csum16);

        update_checksum(
        pp.ipv4_icmp.isValid(),
            { pp.ipv4_icmp.version,
              pp.ipv4_icmp.ihl,
              pp.ipv4_icmp.dscp,
              pp.ipv4_icmp.ecn,
              pp.ipv4_icmp.totalLen,
              pp.ipv4_icmp.identification,
              pp.ipv4_icmp.flags,
              pp.ipv4_icmp.fragOffset,
              pp.ipv4_icmp.ttl,
              pp.ipv4_icmp.protocol,
              pp.ipv4_icmp.srcAddr,
              pp.ipv4_icmp.dstAddr },
              pp.ipv4_icmp.hdrChecksum,
              HashAlgorithm.csum16);

        update_checksum(
        pp.icmp.isValid(),
            { pp.icmp.type,
              pp.icmp.code,
              pp.icmp.unused,
              pp.ipv4.version,
	          pp.ipv4.ihl,
              pp.ipv4.dscp,
              pp.ipv4.ecn,
              pp.ipv4.totalLen,
              pp.ipv4.identification,
              pp.ipv4.flags,
              pp.ipv4.fragOffset,
              pp.ipv4.ttl,
              pp.ipv4.protocol,
              pp.ipv4.hdrChecksum,
              pp.ipv4.srcAddr,
              pp.ipv4.dstAddr,
              pp.tcp.srcPort,
              pp.tcp.dstPort,
              pp.tcp.seqNo
              },
              pp.icmp.checksum,
              HashAlgorithm.csum16);
        }
}

/* ------------------------------------------------------------------------- */
control DeparserImpl(packet_out packet, in Parsed_packet pp) {
    apply {
        packet.emit(pp.ethernet);
        packet.emit(pp.ipv4_icmp);
        packet.emit(pp.icmp);
        packet.emit(pp.ipv4);
        packet.emit(pp.tcp);
    }
}

V1Switch(ParserImpl(),
    verifyChecksum(),
    ingress(),
    egress(),
    computeChecksum(),
    DeparserImpl()) main;
