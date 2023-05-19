from subprocess import Popen
import os
import pandas as pd
import time

i = 0
for i in range(100):
    start = time.time()
    a = str(i)
    commands = [
    "simple_switch_CLI --thrift-port 9090 < command1.txt > Test/attack/exp3/flow_duration/"+ "flow_duration" + a + ".csv" ,
    "simple_switch_CLI --thrift-port 9090 < command2.txt > Test/attack/exp3/flow_size/"+ "flow_size" + a + ".csv" ,
    "simple_switch_CLI --thrift-port 9090 < command3.txt > Test/attack/exp3/flow_key/"+ "flow_index" + a + ".csv" 
    ]
    # run in parallel
    processes = [Popen(cmd, shell=True) for cmd in commands]
    for p in processes: p.wait()
    end = time.time()
    diff = end - start
    if diff != 5:
        time.sleep(5 - diff)
    else:
        continue



