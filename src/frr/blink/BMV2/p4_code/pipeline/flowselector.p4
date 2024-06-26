
control flowselector(inout Parsed_packet pp,
    inout custom_metadata_t custom_metadata,
    inout standard_metadata_t standard_metadata,
    in register<bit<32>> flowselector_key, // Could be just 16 or something bits
    in register<bit<32>> flowselector_nep,
    in register<bit<9>> flowselector_ts,
    in register<bit<19>> flowselector_last_ret,
    in register<bit<4>> flowselector_last_ret_bin,
    in register<bit<1>> flowselector_correctness,
    in register<bit<2>> flowselector_fwloops,
    in register<bit<6>> sw,
    in register<bit<19>> sw_time,
    in register<bit<4>> sw_index,
    in register<bit<6>> sw_sum,
    in register<bit<6>> nbflows_progressing_2,
    in register<bit<6>> nbflows_progressing_3,
    in register<bit<19>> rerouting_ts,
    
    //calculating flow duration
    in register<bit<19>> start_time,
    in register<bit<19>> end_time,
    in register<bit<9>> flow_duration_normal,
    in register<bit<32>> packet_count_normal,
    in register<bit<9>> dump_array,
    in register<bit<32>> dump_fc,
    in register<bit<16>> dst_port,
    in register<bit<32>> offset,
    in register<bit<19>>flow_duration,
    in register<bit<32>> reroute_bit,
    in register<bit<32>> flow_size,
    in register<bit<32>> flowselector_key_attack_index, // to get the attack index for labeling the dataset
    in register<bit<19>> flowselector_ts_fd,
    in register<bit<32>> selected_flow_size,
    in register<bit<32>> flow_size_normal,
    in register<bit<32>> s)
   // in register<bit<32>> offset)
{
    bit<32> newflow_key;
    bit<32> cell_id;

    bit<32> curflow_key;
    bit<9> curflow_ts;
   // bit<16> curDes;
    bit<32> curflow_nep;
    bit<19> ts_tmp;
    bit<10> cnt;

    bit<4> index_tmp;
    bit<6> bin_value_tmp;
    bit<6> sum_tmp;
    bit<19> time_tmp;

    bit<32> flowselector_index;
    bit<19> last_ret_ts;
    bit<4> index_prev;

    bit<19> rerouting_ts_tmp;
    bit<1> flowselector_correctness_tmp;
    bit<6> correctness_tmp;

    bit<19> start;
    bit<19> end;
    bit<19> val;
    bit<32> fc_val;
    bit<32> off;
    bit<32> offset_val;
    bit<32> size;
    bit<32> reroute;

    // register<bit<32>>(32w1) s;
    register<bit<9>>(1) track_time; //to reset the s value to 0 after executing for 10 min
    register<bit<9>>(1) packet_count;

    bit<9> time_t;
    bit<9> pc;

    table dummy1{
        actions = {NoAction;}
        key = {
            end : exact;
            start: exact;
            val: exact;
            custom_metadata.ingress_timestamp_second : exact;
        }
    }

    table dummy2{
        actions = {NoAction;}
        key = {
            end : exact;
            start: exact;
            val: exact;
            custom_metadata.ingress_timestamp_second : exact;
        }
    }
    apply {


        cnt=0;
        #include "sliding_window.p4"

        // -- Original P4 code
        //Compute the hash for the flow key 
        /*hash(newflow_key, HashAlgorithm.crc32, (bit<16>)0,
           {pp.ipv4.srcAddr, pp.ipv4.dstAddr, pp.tcp.srcPort, pp.tcp.dstPort, \
           HASH1_OFFSET}, (bit<32>)(TWO_POWER_32-1)); */
       // newflow_key = newflow_key + 1;
        // -- Original P4 code end

        // Added -- source TCP port to distinguish between a malicious or legitimate flow

        newflow_key = (bit<32>) pp.tcp.srcPort;

        //helps to keep track the time to reset s
        // packet_count.read(pc,32w0);
        // if(pc==0)
        // {
        //     track_time.write(32w0,custom_metadata.ingress_timestamp_second);
        // }
        // pc = pc+1;
        // packet_count.write(32w0,pc);


        //newflow_key=(bit<32>)pp.tcp.dstPort;
       // cnt = cnt + 1;
        //custom_metadata.hash_value=newflow_key;
       // custom_metadata.addr=pp.tcp.dstPort;

        // Compute the hash for the cell id
        hash(cell_id, HashAlgorithm.crc32, (bit<16>)0,
            {pp.ipv4.srcAddr, pp.ipv4.dstAddr, pp.tcp.srcPort, pp.tcp.dstPort, \
                HASH2_OFFSET}, (bit<32>)FLOWSELECTOR_NBFLOWS);

        custom_metadata.flowselector_cellid = cell_id;

        flowselector_index = (custom_metadata.id * FLOWSELECTOR_NBFLOWS) + cell_id;
        flowselector_key.read(curflow_key, flowselector_index);  //read the flow selector key
        flowselector_ts.read(curflow_ts, flowselector_index);   // 
      
        flowselector_nep.read(curflow_nep, flowselector_index);
       // start_time.write(flowselector_index,custom_metadata.ingress_timestamp_second);
       // dst_port.write(custom_metadata.id,pp.tcp.dstPort);
        //dst_addr=pp.tcp.dstPort;

        rerouting_ts.read(rerouting_ts_tmp, custom_metadata.id);

        //here is where we need to add the code to start the timestmp to calculate duration
        //the second condition shows the presence of new packet into that flow
        // if(curflow_ts==0)
        // {
        //     start_time.write(flowselector_index,custom_metadata.ingress_timestamp_second);

        // }
        // else if(pp.tcp.syn == 1w1)
        // {
        //     start_time.write(flowselector_index,custom_metadata.ingress_timestamp_second);

        // }

        //end_time.write(flowselector_index,custom_metadata.ingress_timestamp_second);


        if (curflow_key == newflow_key && custom_metadata.ingress_timestamp_second >= curflow_ts)   //if the ingress timestamp is greater than
        //current flow timestamp
        {
            //the packet  gets selected
            custom_metadata.selected = 1w1;

            //implement the logic to update register for timestamp here
       
            //if it is the last packet of the flow 
            /*
              here is the logic for every packet that comes in
                * see if its last packet
                * otherwise check if it has retransmission
                * else check one more condition
                * the logic is that if its fin packet the flow is evicted automatically 
                *otherwise u need to check if it is inactive for that particular timestamp

            */
            if (pp.tcp.fin == 1w1)
            {
                //this involves the logic of sliding window
                // Retrieve the timestamp of the last retransmission
                flowselector_last_ret.read(last_ret_ts, flowselector_index);

                // Retrieve the timestamp of the current bin
                sw_time.read(time_tmp, custom_metadata.id);

                // If there was a retransmission during the last time window:
                // remove it from the sliding window
                if (((bit<48>)(custom_metadata.ingress_timestamp_millisecond - last_ret_ts)) <
                    (bit<48>)((bit<19>)(SW_NB_BINS-1)*(SW_BINS_DURATION)
                    + (custom_metadata.ingress_timestamp_millisecond - time_tmp))
                    && last_ret_ts > 0)
                {
                    // Read the value of the previous index used for the previous retransmission
                    flowselector_last_ret_bin.read(index_prev, flowselector_index);

                    // Decrement the value in the previous bin in the sliding window,
                    // as well as the total sum
                    sw.read(bin_value_tmp, (custom_metadata.id*(bit<32>)SW_NB_BINS)+(bit<32>)index_prev);
                    sw_sum.read(sum_tmp, custom_metadata.id);

                    sw.write((custom_metadata.id*(bit<32>)SW_NB_BINS)+(bit<32>)index_prev, bin_value_tmp-1);
                    sw_sum.write(custom_metadata.id, sum_tmp-1);
                }

                //if its fin packet reset the index of flowselector to 0
                //since this is terminating flow ,here also u need to find the difference of the timestamps

                reroute_bit.read(reroute, 0); // If reroute already occured, don't update the regsiters. At the end of the experiment, we want to collect the stat
                sw_sum.read(sum_tmp, custom_metadata.id);
                if(sum_tmp > 31)
                reroute_bit.write(0, 1);
                if(reroute == 0)
                {
                start_time.read(start,flowselector_index); // Retrieve the time when 1st packet of the flow arrived
                flowselector_ts_fd.read(end,flowselector_index); // Retrieve the time when last packet of the flow arrived using flowselector_ts
                //try by taking metadata for diffen
                //noting the values
                end_time.write(flowselector_index,end-start); // write the difference
                end_time.read(val,flowselector_index);  // read the flow duration value
                selected_flow_size.read(size, flowselector_index); // read the flow size
		        offset.read(off,32w0); // read the offset value
                //flow_duration_normal.write(off, val); // write flow duration of the evicted flow to eviction array
		        flow_size_normal.write(off,size);
                offset.write(32w0, off+1); // increment the offset

                // Approach 2
                flow_duration.write(flowselector_index, val); // write flow duration of the evicted flow to eviction array -- Not required, since flow is going to get evicted!
                flow_size.write(flowselector_index, size); // write flow size of the evicted flow to eviction array -- Not required, since flow is going to get evicted!
                }
                /*
                    Calling dummy table
                    */
                    dummy2.apply();

                //update the other register as well
                //offset.read(offset_val,32w0);
               // dump_array.write(offset_val,end-start);

            //   s.read(offset_val,32w0);
            //    dump_array.write(offset_val,val);
            //    dump_array.write(offset_val,end-start);
               //dump_array.write(offset_val,end-start); 
              // flowselector_key.read(fc_val,flowselector_index);
               //dump_fc.write((bit<32>)offset_val,fc_val);
             //  offset_val=offset_val+1;
              // s.write(32w0,offset_val);

                //increment the offset value
               // offset_val = offset_val + 1;
               // offset.write(32w0,offset_val);
                

                // Reset all the registers to 0

                flowselector_key.write(flowselector_index, 32w0);
                flowselector_nep.write(flowselector_index, 32w0);
                flowselector_ts.write(flowselector_index, 9w0);
                flowselector_ts_fd.write(flowselector_index, 19w0);
                dst_port.write(flowselector_index,pp.tcp.dstPort);
                flowselector_last_ret.write(flowselector_index, 19w0);
                flowselector_correctness.write(flowselector_index, 1w0);
                flowselector_fwloops.write(flowselector_index, 2w0);
                // flush all the temporary registers used to collect flow stats
                start_time.write(flowselector_index,19w0);
                end_time.write(flowselector_index,19w0);
                selected_flow_size.write(flowselector_index, 32w0);
                
            }

            // else if(pp.tcp.syn == 1w1 )
            // {
            //     start_time.write(flowselector_index,custom_metadata.ingress_timestamp_second);
            // }

            //if the packet is neither last nor first
            //here u might need to update the logic to update the second timestamp

            else // ####### flow is already selected but the packet is not fin i.e if the packet is neither last nor first ############ Update the flowselector_ts
            {
                // If it is a RETRANSMISSION
                if (curflow_nep == pp.tcp.seqNo + (bit<32>)custom_metadata.tcp_payload_len)
                {
                    // Indicate that this packet is a retransmssion
                    custom_metadata.is_retransmission = 1;

                    // Retrieve the timestamp of the last retransmission
                    flowselector_last_ret.read(last_ret_ts, flowselector_index);

                    // Retrieve the timestamp of the current bin
                    sw_time.read(time_tmp, custom_metadata.id);

                    if (((bit<48>)(custom_metadata.ingress_timestamp_millisecond - last_ret_ts)) <
                        (bit<48>)((bit<19>)(SW_NB_BINS-1)*(SW_BINS_DURATION)
                        + (custom_metadata.ingress_timestamp_millisecond - time_tmp))
                        && last_ret_ts > 0)
                    {
                        // Read the value of the previous index used for the previous retransmission
                        flowselector_last_ret_bin.read(index_prev, flowselector_index);
                        
                        // First, decrement the value in the previous bin in the sliding window
                        sw.read(bin_value_tmp, (custom_metadata.id*(bit<32>)SW_NB_BINS)+(bit<32>)index_prev);
                        sw_sum.read(sum_tmp, custom_metadata.id);

                        sw.write((custom_metadata.id*(bit<32>)SW_NB_BINS)+(bit<32>)index_prev, bin_value_tmp-1);
                        sw_sum.write(custom_metadata.id, sum_tmp-1);
                    }

                    // Then, increment the value in the current bin of the sliding window
                    sw_index.read(index_tmp, custom_metadata.id);
                    sw.read(bin_value_tmp, (custom_metadata.id*(bit<32>)SW_NB_BINS)+(bit<32>)index_tmp);
                    sw_sum.read(sum_tmp, custom_metadata.id);

                    sw.write((custom_metadata.id*(bit<32>)SW_NB_BINS)+(bit<32>)index_tmp, bin_value_tmp+1);
                    sw_sum.write(custom_metadata.id, sum_tmp+1);

                    // Update the timestamp of thttps://notes.io/EcBX
                    // Update the timestamp of the last retransmission in the flowselector
                    sw_time.read(time_tmp, custom_metadata.id);
                    flowselector_last_ret.write(flowselector_index, custom_metadata.ingress_timestamp_millisecond);  

                    // Read the value of the previous index used for the previous retransmission
                    flowselector_last_ret_bin.write(flowselector_index, index_tmp);
                }

                /*
                //################ If it is not a retransmission: Update the correctness register (if blink has rerouted) ######
                else if (rerouting_ts_tmp > 19w0 && custom_metadata.ingress_timestamp_millisecond
                    - rerouting_ts_tmp < (bit<19>)TIMEOUT_PROGRESSION)
                {
                    flowselector_correctness.read(flowselector_correctness_tmp,
                        (custom_metadata.id * FLOWSELECTOR_NBFLOWS) + custom_metadata.flowselector_cellid);

                    if (flowselector_correctness_tmp == 1w0)
                    {
                        if (custom_metadata.flowselector_cellid < 32)
                        {
                            nbflows_progressing_2.read(correctness_tmp, custom_metadata.id);
                            nbflows_progressing_2.write(custom_metadata.id, correctness_tmp+1);
                        }
                        else
                        {
                            nbflows_progressing_3.read(correctness_tmp, custom_metadata.id);
                            nbflows_progressing_3.write(custom_metadata.id, correctness_tmp+1);
                        }
                    }

                    flowselector_correctness.write(
                        (custom_metadata.id * FLOWSELECTOR_NBFLOWS) + custom_metadata.flowselector_cellid, 1w1);
                } */
                

                
                
                //offset.read(offset_val,32w0);
                //dump_array.write(flowselector_index+offset_val,end-start);

                flowselector_ts.write(flowselector_index, custom_metadata.ingress_timestamp_second); // Here, we update the flowselector_ts by current timestamp
                flowselector_ts_fd.write(flowselector_index, custom_metadata.ingress_timestamp_millisecond); // Here, we update the flowselector_ts by current timestamp for Flow duration
                flowselector_nep.write(flowselector_index, pp.tcp.seqNo + (bit<32>)custom_metadata.tcp_payload_len);

                reroute_bit.read(reroute, 0); // If reroute already occured, don't update the regsiters. At the end of the experiment, we want to collect the stat
                sw_sum.read(sum_tmp, custom_metadata.id);
                if(sum_tmp > 31)
                reroute_bit.write(0, 1);
                if(reroute == 0)
                {
                start_time.read(start,flowselector_index);
                flowselector_ts_fd.read(end,flowselector_index);
                val = end - start; // Added logic
                end_time.write(flowselector_index,end-start);
                selected_flow_size.read(size, flowselector_index);
		        size = size + (bit<32>)pp.ipv4.totalLen;
		        selected_flow_size.write(flowselector_index, size);

                // Approach 2
                flow_duration.write(flowselector_index, val); // write flow duration calculated till the current packet
                flow_size.write(flowselector_index,size); // write flow size calculated till the current packet

                } 
            }
        }
        else //################# Eviction (> 2s ) or new flow ###############
        {
            //here is the code to evict the flows if its inactive for 2 s 
            //here write a code to calculate the difference of timestamps even
            //If the index of a new flow is same but the flowKey is different(Collision).

            if (((curflow_key == 0) || (custom_metadata.ingress_timestamp_second
                - curflow_ts) > FLOWSELECTOR_TIMEOUT || custom_metadata.ingress_timestamp_second
                < curflow_ts) && pp.tcp.fin == 1w0)
            {
                custom_metadata.selected = 1w1;
                cnt=cnt-1;
            
                // ################# EVICTION #######################
                if (curflow_key > 0) // replace curflow_key flow with newflow_key
                {
                    // Retrieve the timestamp of the last retransmission
                    // This block will remove the flow from Sliding Window.
                    flowselector_last_ret.read(last_ret_ts, flowselector_index);

                    // Retrieve the timestamp of the current bin
                    sw_time.read(time_tmp, custom_metadata.id);

                    // If there was a retransmission during the last time window:
                    // remove it from the sliding window
                    if (((bit<48>)(custom_metadata.ingress_timestamp_millisecond - last_ret_ts)) <
                        (bit<48>)((bit<19>)(SW_NB_BINS-1)*(SW_BINS_DURATION)
                        + (custom_metadata.ingress_timestamp_millisecond - time_tmp))
                        && last_ret_ts > 0)
                    {
                        // Read the value of the previous index used for the previous retransmission
                        flowselector_last_ret_bin.read(index_prev, flowselector_index);

                        // Decrement the value in the previous bin in the sliding window,
                        // as well as the total sum
                        sw.read(bin_value_tmp, (custom_metadata.id*(bit<32>)SW_NB_BINS)+(bit<32>)index_prev);
                        sw_sum.read(sum_tmp, custom_metadata.id);

                        sw.write((custom_metadata.id*(bit<32>)SW_NB_BINS)+(bit<32>)index_prev, bin_value_tmp-1);
                        sw_sum.write(custom_metadata.id, sum_tmp-1);
                    }

                reroute_bit.read(reroute, 0); // If reroute already occured, don't update the regsiters. At the end of the experiment, we want to collect the stat
                sw_sum.read(sum_tmp, custom_metadata.id);
                if(sum_tmp > 31)
                reroute_bit.write(0, 1);
                if(reroute == 0)
                {
                    start_time.read(start,flowselector_index);
                    flowselector_ts_fd.read(end,flowselector_index);
                    end_time.write(flowselector_index,end-start); 
                    val = end - start;               
                    end_time.read(val,flowselector_index);
		            selected_flow_size.read(size, flowselector_index);
                    offset.read(off,32w0); // read the offset value
                    //flow_duration_normal.write(off, val); // write flow duration of the evicted flow to eviction array
		            flow_size_normal.write(off,size); // write flow size of the evicted flow to the eviction array
                    offset.write(32w0, off+1); // increment the offset
                    
                    // Approach 2
                    flow_duration.write(flowselector_index,val); // This flow will anyway going to get evicted!
                    flow_size.write(flowselector_index,size); // This flow will anyway going to get evicted!
                }
                    /*
                    Calling dummy table
                    */
                    //dummy1.apply();

                    //s.read(offset_val,32w0);
                    // dump_array.write(offset_val,val);
                    //dump_array.write(offset_val,end-start);
                    //dump_array.write(offset_val,end-start); 
                    //flowselector_key.read(fc_val,flowselector_index);
                    //dump_fc.write((bit<32>)offset_val,fc_val);
                    //offset_val=offset_val+1;
                    //s.write(32w0,offset_val);
                }

            // ################################# NEW FLOW ##########################################

                //update the other register as well
               //// offset.read(offset_val,32w0);
                //dump_array.write(flowselector_index+offset_val,end-start);

                //increment the offset value
                //offset_val = offset_val + (MAX_NB_PREFIXES*FLOWSELECTOR_NBFLOWS);
                //offset.write(32w0,offset_val);

                //flow is selected for the first time or HARD EVICTION is done, so current flow is evicted and replaced by new flow
                flowselector_key.write(flowselector_index, newflow_key);
                flowselector_nep.write(flowselector_index, pp.tcp.seqNo + (bit<32>)custom_metadata.tcp_payload_len);
                flowselector_ts.write(flowselector_index, custom_metadata.ingress_timestamp_second);
                flowselector_ts_fd.write(flowselector_index, custom_metadata.ingress_timestamp_millisecond);
                dst_port.write(flowselector_index,pp.tcp.dstPort);
                flowselector_last_ret.write(flowselector_index, 19w0);
                flowselector_correctness.write(flowselector_index, 1w0);
                flowselector_fwloops.write(flowselector_index, 2w0);
                selected_flow_size.write(flowselector_index, 32w0);
                start_time.write(flowselector_index,custom_metadata.ingress_timestamp_millisecond); // first packet, write the ingress timestamp
		        selected_flow_size.write(flowselector_index, (bit<32>)pp.ipv4.totalLen);

                reroute_bit.read(reroute, 0); // If reroute already occured, don't update the regsiters. At the end of the experiment, we want to collect the stat
                sw_sum.read(sum_tmp, custom_metadata.id);
                if(sum_tmp > 31)
                reroute_bit.write(0, 1);
                if(reroute == 0)
                {
                flowselector_key_attack_index.write(flowselector_index, newflow_key); // Used to get the flow index labels for debugging purpose
                }
            }
        }
        track_time.read(time_t,0);
        // if(custom_metadata.ingress_timestamp_second-time_t>=MAX_RUN_TIME)
        // {
        //     s.write(32w0,0);

        // }
            
    }
}
