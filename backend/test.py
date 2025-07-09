# import pandas as pd
# import numpy as np
# import os
# from multiprocessing import Queue
# import threading
# from sniff import sniff_and_stream,start_sniffing, process_flows,prepare_input_for_prediction
# import time
# from predict_random import predict_live_flows
# from predict_lgbm import predict_live_flows_lgbm
# # from predict_anomaly import predict_live_flows_autoencoder

# if __name__ == '__main__':
#     flow_queue = start_sniffing(interface="Ethernet 4", window=20)

# # Continuously process new DataFrames from the queue
#     while True:
#         if not flow_queue.empty():
#             df = flow_queue.get()
#             predictions = predict_live_flows(df)
#             # if float(predictions["confidence"]) > 6:
#             print(f"Predictions: {predictions}")

from scapy.all import sniff

def handle_packet(pkt):
    print(pkt.summary())  # or call your detection logic here

sniff(iface="Ethernet 4", prn=handle_packet, store=0)
# from scapy.all import conf
# for iface in conf.ifaces.values():
#     print(f"Name: {iface.name} | Description: {iface.description}")