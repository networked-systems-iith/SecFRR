from pcap_parser import pcap_reader
import os
import csv

input = "E:\\IITH\\BLINK\\CAIDA\\RoutScout\\codes\\attack-new\\A1-attack\\60secs-new\\"
#input_attack = "/home/netx3/RoutScout/attack_pcaps/"
#output_json = "/home/netx3/RoutScout/python_code/FRR/JSON-normal/"
#output_csv= "/home/netx3/RoutScout/python_code/FRR/CSV-normal/"

output_csv = "E:\\IITH\\BLINK\\CAIDA\\RoutScout\\codes\\attack-new\\A1-CSV-attack\\60secs-new\\"
output_json= "E:\\IITH\\BLINK\\CAIDA\\RoutScout\\codes\\attack-new\\A1-JSON-attack\\60secs-new\\"

files = os.listdir(input)
print(files)

for file in files:
    file_name, file_extension = os.path.splitext(file)
    if file.endswith('-1RTT.pcap') and file_extension == '.pcap':
        
        delA_delB, list_delaysA, list_delaysB = pcap_reader(input + file)
        

        with open(output_csv + file_name + '.csv','w') as f:
            csv_writer = csv.writer(f)
            field = ['Avg_DelayA','Avg_DelayB','Avg_DelA-Avg_DelB','fcount_A','fcount_B','Percentage difference']
            csv_writer.writerow(field)
            csv_writer.writerows(delA_delB)

        json_data = {
            "DelayA": list_delaysA,
            "DelayB": list_delaysB
        }

        import json
        with open(output_json + file_name + '.json', 'w') as json_file:
            json.dump(json_data, json_file)

