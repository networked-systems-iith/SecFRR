from pcap_parser import pcap_reader
import os
import csv

input = # input directory containing pcaps
output_csv = # output directory to store csv generated for each pcap
output_json= # output directory to store json generated for each pcap

files = os.listdir(input)
print(files)

for file in files:
    file_name, file_extension = os.path.splitext(file)
    if file_extension == '.pcap':
        
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
