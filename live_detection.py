import subprocess
import time
import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
import pickle

import firebase_admin
from firebase_admin import db, credentials


def run_captures(source_ip):
    

    interface = "Ethernet"  # Replace with the actual interface name
    capture_duration = 10  # Capture duration in seconds

    # Construct the tshark command
    command = [
        "tshark",
        "-i", interface,
        "-w", "captured_pac.pcap",
        "-a", f"duration:{capture_duration}",
        '-f',f'ip src {source_ip}'
    ]
    subprocess.run(command)

def run_tshark_command(input_file, output_file):
    tshark_cmd = [
        'tshark',
        '-r', input_file,
        '-E', 'header=y',
        '-E', 'separator=,',
        '-T', 'fields',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', 'ip.proto',
        '-e', 'eth.src',
        '-e', 'eth.dst',
        '-e', 'ipv6.src',
        '-e', 'ipv6.dst',
        '-e', 'ip.ttl',
        '-e', 'ip.id',
        '-e', 'ip.hdr_len',
        '-e', 'ip.len',
        '-e', 'ip.flags.df',
        '-e', 'tcp.stream',
        '-e', 'tcp.time_delta',
        '-e', 'tcp.time_relative',
        '-e', 'tcp.analysis.initial_rtt',
        '-e', 'tcp.flags',
        '-e', 'tcp.window_size_value',
        '-e', 'tcp.hdr_len',
        '-e', 'tcp.len',
        '-e','tcp.srcport',
        '-e','tcp.dstport',
        '-e', 'udp.srcport',
        '-e', 'udp.dstport',
        '-e', 'udp.stream',
        '-e', 'udp.length',
        '-e', 'icmp.length',
        '-e', 'http.request.method',
        '-e', 'http.response.code',
        '-e', 'http.content_length',
        '-e', 'ip.ttl'
    ]

    try:
        # Open a file for writing the output
        with open(output_file, 'w') as output:
            # Run the Tshark command and capture the output
            process = subprocess.Popen(tshark_cmd, stdout=output, stderr=subprocess.PIPE, text=True)

            # Wait for the process to finish
            stdout, stderr = process.communicate()
            print("STDOUT:")
            print(stdout)

            print("STDERR:")
            print(stderr)            # Print any errors
            if process.returncode != 0:
                print("Error:", process.stderr)

    except Exception as e:
        print("An error occurred:", str(e))



if __name__ == '__main__':

# Example: Run Tshark command and save output to 'myfile.csv'
    #source_ip = '192.168.18.119'
    #run_captures(source_ip)

    #time.sleep(5)
    run_tshark_command('corvit_test_rstp_1.pcapng', 'corvit_test_rtsp.csv')
    
    #with open('model.pkl','rb') as f:
    #    model = pickle.load(f)

    #df6 = pd.read_csv('captured_pac.csv')
    #df6 = df6.fillna(0)
    #df6 = df6.drop(['ip.src','ip.dst','ipv6.src','ipv6.dst','eth.src','eth.dst','ip.id','tcp.flags','ipv6.dst','ip.ttl','icmp.length','http.request.method','http.response.code','http.content_length'],axis = 1)
    #df6 = pd.get_dummies(df6)
    #predictions = model.predict(df6)
    #pJ = {'predictions':predictions.tolist()}
    
    #creds = credentials.Certificate('creds.json')
    #firebase_admin.initialize_app(creds, {'databaseURL':'https://mldetection-674be-default-rtdb.firebaseio.com/'})

    #ref = db.reference('/')
    #ref.set(pJ)
