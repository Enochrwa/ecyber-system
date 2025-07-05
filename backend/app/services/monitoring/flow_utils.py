import os
import time
import threading
import numpy as np
import pandas as pd
from multiprocessing import Queue
from scapy.all import sniff
from cicflowmeter.flow_session import FlowSession



# Step 4: Rename internal feature names to CICIDS2017 format
RENAME_MAP = {
    "dst_port": "Destination Port",
    "flow_duration": "Flow Duration",
    "tot_fwd_pkts": "Total Fwd Packets",
    "tot_bwd_pkts": "Total Backward Packets",
    "totlen_fwd_pkts": "Total Length of Fwd Packets",
    "totlen_bwd_pkts": "Total Length of Bwd Packets",
    "fwd_pkt_len_max": "Fwd Packet Length Max",
    "fwd_pkt_len_min": "Fwd Packet Length Min",
    "fwd_pkt_len_mean": "Fwd Packet Length Mean",
    "fwd_pkt_len_std": "Fwd Packet Length Std",
    "bwd_pkt_len_max": "Bwd Packet Length Max",
    "bwd_pkt_len_min": "Bwd Packet Length Min",
    "bwd_pkt_len_mean": "Bwd Packet Length Mean",
    "bwd_pkt_len_std": "Bwd Packet Length Std",
    "flow_byts_s": "Flow Bytes/s",
    "flow_pkts_s": "Flow Packets/s",
    "flow_iat_mean": "Flow IAT Mean",
    "flow_iat_std": "Flow IAT Std",
    "flow_iat_max": "Flow IAT Max",
    "flow_iat_min": "Flow IAT Min",
    "fwd_iat_tot": "Fwd IAT Total",
    "fwd_iat_mean": "Fwd IAT Mean",
    "fwd_iat_std": "Fwd IAT Std",
    "fwd_iat_max": "Fwd IAT Max",
    "fwd_iat_min": "Fwd IAT Min",
    "bwd_iat_tot": "Bwd IAT Total",
    "bwd_iat_mean": "Bwd IAT Mean",
    "bwd_iat_std": "Bwd IAT Std",
    "bwd_iat_max": "Bwd IAT Max",
    "bwd_iat_min": "Bwd IAT Min",
    "fwd_psh_flags": "Fwd PSH Flags",
    "fwd_urg_flags": "Fwd URG Flags",
    "fwd_header_len": "Fwd Header Length",
    "bwd_header_len": "Bwd Header Length",
    "fwd_pkts_s": "Fwd Packets/s",
    "bwd_pkts_s": "Bwd Packets/s",
    "pkt_len_min": "Min Packet Length",
    "pkt_len_max": "Max Packet Length",
    "pkt_len_mean": "Packet Length Mean",
    "pkt_len_std": "Packet Length Std",
    "pkt_len_var": "Packet Length Variance",
    "fin_flag_cnt": "FIN Flag Count",
    "syn_flag_cnt": "SYN Flag Count",
    "rst_flag_cnt": "RST Flag Count",
    "psh_flag_cnt": "PSH Flag Count",
    "ack_flag_cnt": "ACK Flag Count",
    "urg_flag_cnt": "URG Flag Count",
    "ece_flag_cnt": "ECE Flag Count",
    "cwr_flag_count": "CWE Flag Count",
    "down_up_ratio": "Down/Up Ratio",
    "pkt_size_avg": "Average Packet Size",
    "fwd_seg_size_avg": "Avg Fwd Segment Size",
    "bwd_seg_size_avg": "Avg Bwd Segment Size",
    "fwd_header_len": "Fwd Header Length.1",
    "subflow_fwd_pkts": "Subflow Fwd Packets",
    "subflow_fwd_byts": "Subflow Fwd Bytes",
    "subflow_bwd_pkts": "Subflow Bwd Packets",
    "subflow_bwd_byts": "Subflow Bwd Bytes",
    "init_fwd_win_byts": "Init_Win_bytes_forward",
    "init_bwd_win_byts": "Init_Win_bytes_backward",
    "fwd_act_data_pkts": "act_data_pkt_fwd",
    "fwd_seg_size_min": "min_seg_size_forward",
    "active_mean": "Active Mean",
    "active_std": "Active Std",
    "active_max": "Active Max",
    "active_min": "Active Min",
    "idle_mean": "Idle Mean",
    "idle_std": "Idle Std",
    "idle_max": "Idle Max",
    "idle_min": "Idle Min"
}

# Rename columns

# Step 5: Select only required columns (these 40+ exact names)
SELECTED_FEATURES = [
    "Destination Port", "Flow Duration", "Total Length of Fwd Packets",
    "Fwd Packet Length Min", "Bwd Packet Length Max", "Bwd Packet Length Min",
    "Bwd Packet Length Mean", "Bwd Packet Length Std", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Fwd IAT Total", "Fwd IAT Mean",
    "Fwd IAT Std", "Fwd IAT Max", "Bwd IAT Total", "Bwd IAT Mean",
    "Bwd IAT Std", "Bwd IAT Max", "Bwd Packets/s", "Min Packet Length",
    "Max Packet Length", "Packet Length Mean", "Packet Length Std",
    "Packet Length Variance", "FIN Flag Count", "SYN Flag Count",
    "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "Down/Up Ratio",
    "Average Packet Size", "Avg Bwd Segment Size", "Subflow Fwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "Idle Mean",
    "Idle Std", "Idle Max", "Idle Min"
]

def process_flows(raw_df: pd.DataFrame):
    """
    Post-processes raw flow DataFrame:
      - Renames columns
      - Selects needed features
      - Fills missing values
    """
    if raw_df is None or raw_df.empty:
        return pd.DataFrame()

    # Rename & select columns
    df = raw_df.rename(columns=RENAME_MAP)
    existing = [c for c in SELECTED_FEATURES if c in df.columns]
    df_final = df[existing].copy()

    # Fill numeric missing with median
    numeric = df_final.select_dtypes(include=[np.number]).columns
    if len(numeric):
        df_final[numeric] = df_final[numeric].fillna(df_final[numeric].median())

    # Fill non-numeric with mode or 'unknown'
    non_numeric = df_final.select_dtypes(exclude=[np.number]).columns
    for col in non_numeric:
        if df_final[col].isnull().any():
            mode = df_final[col].mode()
            fill = mode.iloc[0] if not mode.empty else 'unknown'
            df_final[col].fillna(fill, inplace=True)

    return df_final


def prepare_input_for_prediction(df_final: pd.DataFrame) -> np.ndarray:
    """
    Reorders columns and converts to numpy array for ML.

    Raises:
        ValueError if features missing or non-numeric.
    """
    # Check missing
    missing = [f for f in SELECTED_FEATURES if f not in df_final.columns]
    if missing:
        raise ValueError(f"Missing expected features: {missing}")

    df_ordered = df_final[SELECTED_FEATURES]

    if df_ordered.empty:
        return np.empty((0, 0))

    # Ensure it's a DataFrame, not Series
    if isinstance(df_ordered, pd.Series):
        df_ordered = df_ordered.to_frame()

    # Check for non-numeric data
    non_numeric_cols = df_ordered.select_dtypes(exclude=[np.number]).columns
    if len(non_numeric_cols) > 0:
        raise ValueError(f"Non-numeric columns detected: {list(non_numeric_cols)}")

    return df_ordered.values



def sniff_and_stream(interface: str, queue:Queue,window: int = 30):
    """
    Continuously sniff live traffic, flush every `window` seconds,
    process flows and send ready feature vectors to ML.
    """
    session = FlowSession(output_mode="csv", output=None, verbose=False)

    def packet_handler(pkt):
        session.process(pkt)

    def flush_loop():
        while True:
            time.sleep(window)
            raw = session.flush_flows(return_dataframe=True)
            df_clean = process_flows(raw)
            if not df_clean.empty:
                for i, row in df_clean.iterrows():
                    features = row.to_dict()
                    vector = prepare_input_for_prediction(pd.DataFrame([row]))
                    queue.put((features, vector))

    # Start sniffing thread
    sniff_thread = threading.Thread(
        target=lambda: sniff(prn=packet_handler, store=0, iface=interface),
        daemon=True
    )
    sniff_thread.start()

    # Start flush/send loop
    flush_loop()


def start_sniffing(interface='Wi-Fi', window=30):
    """
    Starts sniffing in a background thread and returns the feature queue.
    """
    q = Queue()

    # Run in thread so caller can consume queue in parallel
    sniff_thread = threading.Thread(
        target=sniff_and_stream,
        args=(interface, q,window),
        daemon=True
    )
    sniff_thread.start()

    return q


def get_latest_vectors(queue):
    """
    Flushes the queue and returns the most recent item.
    """
    latest = None
    while not queue.empty():
        latest = queue.get()
    return latest



