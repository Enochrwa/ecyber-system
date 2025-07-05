import pandas as pd
import numpy as np
import os
from multiprocessing import Queue
import threading
from sniff import sniff_and_stream,start_sniffing, process_flows,prepare_input_for_prediction
import time
# RENAME_MAP = {
#     "dst_port": "Destination Port",
#     "flow_duration": "Flow Duration",
#     "tot_fwd_pkts": "Total Fwd Packets",
#     "tot_bwd_pkts": "Total Backward Packets",
#     "totlen_fwd_pkts": "Total Length of Fwd Packets",
#     "totlen_bwd_pkts": "Total Length of Bwd Packets",
#     "fwd_pkt_len_max": "Fwd Packet Length Max",
#     "fwd_pkt_len_min": "Fwd Packet Length Min",
#     "fwd_pkt_len_mean": "Fwd Packet Length Mean",
#     "fwd_pkt_len_std": "Fwd Packet Length Std",
#     "bwd_pkt_len_max": "Bwd Packet Length Max",
#     "bwd_pkt_len_min": "Bwd Packet Length Min",
#     "bwd_pkt_len_mean": "Bwd Packet Length Mean",
#     "bwd_pkt_len_std": "Bwd Packet Length Std",
#     "flow_byts_s": "Flow Bytes/s",
#     "flow_pkts_s": "Flow Packets/s",
#     "flow_iat_mean": "Flow IAT Mean",
#     "flow_iat_std": "Flow IAT Std",
#     "flow_iat_max": "Flow IAT Max",
#     "flow_iat_min": "Flow IAT Min",
#     "fwd_iat_tot": "Fwd IAT Total",
#     "fwd_iat_mean": "Fwd IAT Mean",
#     "fwd_iat_std": "Fwd IAT Std",
#     "fwd_iat_max": "Fwd IAT Max",
#     "fwd_iat_min": "Fwd IAT Min",
#     "bwd_iat_tot": "Bwd IAT Total",
#     "bwd_iat_mean": "Bwd IAT Mean",
#     "bwd_iat_std": "Bwd IAT Std",
#     "bwd_iat_max": "Bwd IAT Max",
#     "bwd_iat_min": "Bwd IAT Min",
#     "fwd_psh_flags": "Fwd PSH Flags",
#     "fwd_urg_flags": "Fwd URG Flags",
#     "fwd_header_len": "Fwd Header Length",
#     "bwd_header_len": "Bwd Header Length",
#     "fwd_pkts_s": "Fwd Packets/s",
#     "bwd_pkts_s": "Bwd Packets/s",
#     "pkt_len_min": "Min Packet Length",
#     "pkt_len_max": "Max Packet Length",
#     "pkt_len_mean": "Packet Length Mean",
#     "pkt_len_std": "Packet Length Std",
#     "pkt_len_var": "Packet Length Variance",
#     "fin_flag_cnt": "FIN Flag Count",
#     "syn_flag_cnt": "SYN Flag Count",
#     "rst_flag_cnt": "RST Flag Count",
#     "psh_flag_cnt": "PSH Flag Count",
#     "ack_flag_cnt": "ACK Flag Count",
#     "urg_flag_cnt": "URG Flag Count",
#     "ece_flag_cnt": "ECE Flag Count",
#     "cwr_flag_count": "CWE Flag Count",
#     "down_up_ratio": "Down/Up Ratio",
#     "pkt_size_avg": "Average Packet Size",
#     "fwd_seg_size_avg": "Avg Fwd Segment Size",
#     "bwd_seg_size_avg": "Avg Bwd Segment Size",
#     "fwd_header_len": "Fwd Header Length.1",
#     "subflow_fwd_pkts": "Subflow Fwd Packets",
#     "subflow_fwd_byts": "Subflow Fwd Bytes",
#     "subflow_bwd_pkts": "Subflow Bwd Packets",
#     "subflow_bwd_byts": "Subflow Bwd Bytes",
#     "init_fwd_win_byts": "Init_Win_bytes_forward",
#     "init_bwd_win_byts": "Init_Win_bytes_backward",
#     "fwd_act_data_pkts": "act_data_pkt_fwd",
#     "fwd_seg_size_min": "min_seg_size_forward",
#     "active_mean": "Active Mean",
#     "active_std": "Active Std",
#     "active_max": "Active Max",
#     "active_min": "Active Min",
#     "idle_mean": "Idle Mean",
#     "idle_std": "Idle Std",
#     "idle_max": "Idle Max",
#     "idle_min": "Idle Min"
# }



# SELECTED_FEATURES = [
#     "Destination Port", "Flow Duration", "Total Length of Fwd Packets",
#     "Fwd Packet Length Min", "Bwd Packet Length Max", "Bwd Packet Length Min",
#     "Bwd Packet Length Mean", "Bwd Packet Length Std", "Flow IAT Mean",
#     "Flow IAT Std", "Flow IAT Max", "Fwd IAT Total", "Fwd IAT Mean",
#     "Fwd IAT Std", "Fwd IAT Max", "Bwd IAT Total", "Bwd IAT Mean",
#     "Bwd IAT Std", "Bwd IAT Max", "Bwd Packets/s", "Min Packet Length",
#     "Max Packet Length", "Packet Length Mean", "Packet Length Std",
#     "Packet Length Variance", "FIN Flag Count", "SYN Flag Count",
#     "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "Down/Up Ratio",
#     "Average Packet Size", "Avg Bwd Segment Size", "Subflow Fwd Bytes",
#     "Init_Win_bytes_forward", "Init_Win_bytes_backward", "Idle Mean",
#     "Idle Std", "Idle Max", "Idle Min"
# ]



# def process_flows(temp_csv_path="temp_output.csv"):
#     """
#     Reads raw flow CSV, renames columns, selects needed features,
#     handles missing values, and returns final DataFrame.
#     """
#     if not os.path.exists(temp_csv_path):
#         print(f"❌ File not found: {temp_csv_path}")
#         return pd.DataFrame()

#     df = pd.read_csv(temp_csv_path)
#     if df.empty:
#         print("❌ Flow CSV is empty.")
#         return pd.DataFrame()

#     # Rename columns
#     df.rename(columns=RENAME_MAP, inplace=True)

#     # Select only expected features that exist
#     existing_cols = [col for col in SELECTED_FEATURES if col in df.columns]
#     df_final = df[existing_cols].copy()

#     # Fill numeric missing values with median
#     numeric_cols = df_final.select_dtypes(include=[np.number]).columns
#     df_final[numeric_cols] = df_final[numeric_cols].fillna(df_final[numeric_cols].median())

#     # Fill any non-numeric missing (safeguard)
#     non_numeric_cols = df_final.select_dtypes(exclude=[np.number]).columns
#     for col in non_numeric_cols:
#         if df_final[col].isnull().any():
#             df_final[col].fillna(df_final[col].mode().iloc[0] if not df_final[col].mode().empty else "unknown", inplace=True)

#     return df_final

# def prepare_input_for_prediction(df_final):
#     """
#     Ensures final DataFrame is aligned with EXPECTED_FEATURES
#     and converts it into feature vectors ready for ML prediction.

#     Args:
#         df_final (pd.DataFrame): Cleaned flow DataFrame

#     Returns:
#         np.ndarray: Feature vectors in correct order
#     """
#     # Check for missing expected features
#     missing = [feat for feat in SELECTED_FEATURES if feat not in df_final.columns]
#     if missing:
#         raise ValueError(f"❌ Missing expected features: {missing}")

#     # Select and reorder columns
#     df_ordered = df_final[SELECTED_FEATURES].copy()

#     # Convert to numpy array
#     if df_ordered.empty:
#         print("⚠️ DataFrame is empty. Returning empty array.")
#         return np.empty((0, 0))

#     if not all(np.issubdtype(dtype, np.number) for dtype in df_ordered.dtypes):
#         raise ValueError("❌ DataFrame contains non-numeric values. Ensure all features are numeric before vectorizing.")

#     feature_vectors = df_ordered.values
#     print(f"✅ Feature vectors shape: {feature_vectors.shape}")
#     return feature_vectors


# At the top

# At the bottom


def get_latest_vectors(queue):
    """
    Flushes the queue and returns the most recent item.
    """
    latest = None
    while not queue.empty():
        latest = queue.get()
    return latest


def process_vectors(vectors):
    print(f"📦 Got fresh batch: {vectors.shape}")

if __name__ == '__main__':
    q = start_sniffing(interface='enp0s8', window=30, label="normal")

    print("✅ Sniffer running...")

    while True:
        time.sleep(1)  # Control the poll rate
        vectors = get_latest_vectors(q)
        if vectors is not None:
            process_vectors(vectors)


df = pd.read_csv("test.csv")

df_final = process_flows(df)
vectors = prepare_input_for_prediction(df_final)

# print(f"Shape of dataframe {df_final.shape}")
# print(f"Shape of vectors {vectors.shape}")
# print(df_final.dtypes)
# print(vectors.dtypes)
