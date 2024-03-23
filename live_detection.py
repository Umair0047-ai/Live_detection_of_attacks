import subprocess
import time
import pandas as pd
import numpy as np
#import seaborn as sns
import matplotlib.pyplot as plt
import pickle
from sklearn.metrics import classification_report,confusion_matrix,plot_confusion_matrix,accuracy_score
import firebase_admin
from firebase_admin import db, credentials
from sklearn.metrics import classification_report,confusion_matrix,plot_confusion_matrix,accuracy_score
import seaborn as sns


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


def tcp_run_captures(source_ip):
    

    interface = 'Ethernet'  # Replace with the actual interface name
    #interface = 'Wi-fi'
    capture_duration = 20  # Capture duration in seconds
    # Construct the tshark command
    command = [
        "tshark",
        "-i", interface,
        "-w", "tcp_captured_pac.pcap",
        "-a", f"duration:{capture_duration}",
        '-f',f'ip src {source_ip} or ip dst 192.168.1.56 and tcp'
    ]
    subprocess.run(command)



def udp_run_captures(source_ip):

    interface = 'Ethernet'  # Replace with the actual interface name
    #interface = 'Wi-fi'
    capture_duration = 35  # Capture duration in seconds 355 fast

    # Construct the tshark command
    command = [
        "tshark",
        "-i", interface,
        "-w", "bal_udp_captured_pac.pcap",
        "-a", f"duration:{capture_duration}",
        '-f',f' ip src {source_ip} and udp'
    ]
    subprocess.run(command)

def rtsp_run_captures():
    
    interface = 'Ethernet'  # Replace with the actual interface name
    #interface = 'Wi-fi'
    capture_duration = 97  # Capture duration in seconds- 392

    # Construct the tshark command
    command = [
        "tshark",
        "-i", interface,
        "-w", "bal_rtsp_captured_pac.pcap",
        "-a", f"duration:{capture_duration}",
        '-f', f'port 554'
    ]
    subprocess.run(command)


def Normal_run_captures():
    
    interface = 'Ethernet'  # Replace with the actual interface name
    #interface = 'Wi-fi'
    capture_duration = 50  # Capture duration in seconds

    # Construct the tshark command
    command = [
        "tshark",
        "-i", interface,
        "-w", "bal_Normal_captured_pac.pcap",
        "-a", f"duration:{capture_duration}"
    ]
    subprocess.run(command)

if __name__ == '__main__':

# Example: Run Tshark command and save output to 'myfile.csv'
    
    ## making the tcp
    start_time_captures = time.time()
    source_ip = '192.168.1.69'
    tcp_run_captures(source_ip)
    run_tshark_command('bal_tcp_captured_pac_1.pcap.pcap', 'bal_tcp_captured_pac.csv')
    
    ## making the udp
    
    udp_run_captures(source_ip)
    run_tshark_command('bal_udp_captured_pac.pcap', 'bal_udp_captured_pac.csv')

    ## making the rtsp

    rtsp_run_captures() 
    run_tshark_command('bal_rtsp_captured_pac.pcap', 'bal_rtsp_captured_pac.csv')
    
    ## making normal_traffic
    Normal_run_captures()
    run_tshark_command('bal_Normal_captured_pac.pcap','bal_Normal_captured_pac.csv')
    
    end_time_captures = time.time()
    tot_time_captures = end_time_captures - start_time_captures
    print("The process of creating and extraction takes :",tot_time_captures)

#1. RANDOM FOREST

    start_time_loading_model = time.time()

    with open('un_balanced_model_RF.pkl','rb') as f:
       model_Rf = pickle.load(f)
    end_time_loading_model = time.time()

    tot_time_loading_model = end_time_loading_model - start_time_loading_model
    print("The process of loading the model:",tot_time_loading_model)

    ## data preprocessing
    ## 1. loading the data
    ## 2. removing the features
    ## 3. Cutting the data into frames and labeling the data.
    ## 4. Combining it to get the accuracy
    
    start_time_preprocessing = time.time()

    df1 = pd.read_csv('bal_tcp_captured_pac.csv')
    df1 = df1.fillna(0)
    
    df2 = pd.read_csv('bal_udp_captured_pac.csv')
    df2 = df2.fillna(0)

    df3 = pd.read_csv('bal_rtsp_captured_pac.csv')
    df3 = df3.fillna(0)

    df4 = pd.read_csv('bal_Normal_captured_pac.csv')
    df4 = df4.fillna(0)
    
    df1 = df1.drop(['ip.src','ip.dst','ipv6.src','ipv6.dst','eth.src','eth.dst','ip.id','tcp.flags','ipv6.dst','ip.ttl','icmp.length','http.request.method','http.response.code','http.content_length'],axis = 1)
    df1 = pd.get_dummies(df1)
    df1['attack_type'] = 'TCP_flood'
    
    # ## size for the udp_attack
    
    df2 = df2.drop(['ip.src','ip.dst','ipv6.src','ipv6.dst','eth.src','eth.dst','ip.id','tcp.flags','ipv6.dst','ip.ttl','icmp.length','http.request.method','http.response.code','http.content_length'],axis = 1)
    df2 = pd.get_dummies(df2)
    df2['attack_type'] = 'Udp_flood'

    ## size for the rtsp_attack
    df3 = df3.drop(['ip.src','ip.dst','ipv6.src','ipv6.dst','eth.src','eth.dst','ip.id','tcp.flags','ipv6.dst','ip.ttl','icmp.length','http.request.method','http.response.code','http.content_length'],axis = 1)
    df3 = pd.get_dummies(df3)
    df3['attack_type'] = 'Brute_force'

    df4 = df4.drop(['ip.src','ip.dst','ipv6.src','ipv6.dst','eth.src','eth.dst','ip.id','tcp.flags','ipv6.dst','ip.ttl','icmp.length','http.request.method','http.response.code','http.content_length'],axis = 1)
    df4 = pd.get_dummies(df4)
    df4['attack_type'] = 'Normal_traffic'

    #df5 = df5.drop(['ip.src','ip.dst','ipv6.src','ipv6.dst','eth.src','eth.dst','ip.id','tcp.flags','ipv6.dst','ip.ttl','icmp.length','http.request.method','http.response.code','http.content_length'],axis = 1)
    #df5 = pd.get_dummies(df5)
    #df5['attack_type'] = 'Http_flood'

    
    frames = [df1,df2,df3,df4]
    res = pd.concat(frames)
    
    y1 = res['attack_type']
    X1 = res.drop('attack_type',axis=1)

    end_time_preprocessing = time.time()
    tot_time_preprocessing = end_time_preprocessing - start_time_preprocessing
    print("Total_prcocessing_Time",tot_time_preprocessing)

    
    start_time_model_prediction = time.time()

    predictions = model_Rf.predict(X1)

    end_time_model_prediction = time.time()

    tot_time_prediction = end_time_model_prediction - start_time_model_prediction
    
    print("prediction_time_for_Random_forest",tot_time_prediction)
    acc = (y1==predictions).mean()
    print("Accuracy",acc)
    
    report = classification_report(y1,predictions)
    print(report)
    conf = confusion_matrix(y1,predictions)
    print(conf)
   
##2. NAIVE BAYES:
    
    
    start_time_loading_model = time.time()

    with open('un_balanced_model_NB.pkl','rb') as f:
       model_NB = pickle.load(f)
    end_time_loading_model = time.time()

    tot_time_loading_model = end_time_loading_model - start_time_loading_model
    print("The process of loading the model:",tot_time_loading_model)


    end_time_preprocessing = time.time()
    tot_time_preprocessing = end_time_preprocessing - start_time_preprocessing
    print("Total_prcocessing_Time",tot_time_preprocessing)

    
    start_time_model_prediction = time.time()

    predictions = model_NB.predict(X1)

    end_time_model_prediction = time.time()

    tot_time_prediction = end_time_model_prediction - start_time_model_prediction
    
    print("prediction_time_for_NAIVE_BAYES",tot_time_prediction)
    acc = (y1==predictions).mean()
    print("Accuracy",acc)
    
    report = classification_report(y1,predictions)
    print(report)
    conf = confusion_matrix(y1,predictions)
    print(conf)
   
   
##3. LOG REGRESSION
    
    start_time_loading_model = time.time()

    with open('un_balanced_model_LG.pkl','rb') as f:
       model_LG = pickle.load(f)
    end_time_loading_model = time.time()

    tot_time_loading_model = end_time_loading_model - start_time_loading_model
    print("The process of loading the model:",tot_time_loading_model)   
   
    end_time_preprocessing = time.time()
    tot_time_preprocessing = end_time_preprocessing - start_time_preprocessing
    print("Total_prcocessing_Time",tot_time_preprocessing)

    
    start_time_model_prediction = time.time()

    predictions = model_LG.predict(X1)

    end_time_model_prediction = time.time()

    tot_time_prediction = end_time_model_prediction - start_time_model_prediction
    
    print("prediction_time_for_LOG_REGRESSION:",tot_time_prediction)
    acc = (y1==predictions).mean()
    print("Accuracy",acc)
    
    report = classification_report(y1,predictions)
    print(report)
    conf = confusion_matrix(y1,predictions)
    print(conf)
   
   ##4. ADABOOST 
     
    start_time_loading_model = time.time()

    with open('un_balanced_model_AB.pkl','rb') as f:
       model_AB = pickle.load(f)
    end_time_loading_model = time.time()

    tot_time_loading_model = end_time_loading_model - start_time_loading_model
    print("The process of loading the model:",tot_time_loading_model)   
   
    end_time_preprocessing = time.time()
    tot_time_preprocessing = end_time_preprocessing - start_time_preprocessing
    print("Total_prcocessing_Time",tot_time_preprocessing)

    
    start_time_model_prediction = time.time()

    predictions = model_AB.predict(X1)

    end_time_model_prediction = time.time()

    tot_time_prediction = end_time_model_prediction - start_time_model_prediction
    
    print("prediction_time_for_ADA_BOOST:",tot_time_prediction)
    acc = (y1==predictions).mean()
    print("Accuracy",acc)
    
    report = classification_report(y1,predictions)
    print(report)
    conf = confusion_matrix(y1,predictions)
    print(conf)
   
    ##5. PERCEPTRON
    
    start_time_loading_model = time.time()

    with open('un_balanced_model_PP.pkl','rb') as f:
       model_PP = pickle.load(f)
    end_time_loading_model = time.time()

    tot_time_loading_model = end_time_loading_model - start_time_loading_model
    print("The process of loading the model:",tot_time_loading_model)   
   
    end_time_preprocessing = time.time()
    tot_time_preprocessing = end_time_preprocessing - start_time_preprocessing
    print("Total_prcocessing_Time",tot_time_preprocessing)

    
    start_time_model_prediction = time.time()

    predictions = model_PP.predict(X1)

    end_time_model_prediction = time.time()

    tot_time_prediction = end_time_model_prediction - start_time_model_prediction
    
    print("prediction_time_for_PERCEPTRON:",tot_time_prediction)
    acc = (y1==predictions).mean()
    print("Accuracy",acc)
    
    report = classification_report(y1,predictions)
    print(report)
    conf = confusion_matrix(y1,predictions)
    print(conf)
   
   
    #pJ = {'predictions':predictions.tolist()}
    
    #creds = credentials.Certificate('creds.json')
    #firebase_admin.initialize_app(creds, {'databaseURL':'https://mldetection-674be-default-rtdb.firebaseio.com/'})

    #ref = db.reference('/')
    #ref.set(pJ)
