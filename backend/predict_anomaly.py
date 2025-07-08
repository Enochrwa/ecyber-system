import os
import json
import joblib
import numpy as np
import pandas as pd
from scipy.spatial import distance
from tensorflow.keras.models import load_model

# === Constants ===
FEATURE_COLS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Avg Fwd Bytes/Bulk", "Avg Bwd Bytes/Bulk", "Avg Fwd Packets/Bulk",
    "Avg Bwd Packets/Bulk", "Fwd Bulk Rate Avg", "Bwd Bulk Rate Avg", "Flow Bytes/s",
    "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Fwd URG Flags", "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
    "Avg Fwd Segment Size", "Avg Bwd Segment Size", "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward",
    "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]

MODEL_DIR = "trained_ml/ML/autoencoder_ensemble1/20250705_103912/"
SAVE_PATH = "predictions/anomaly/autoencoder_anomaly_results.json"

def predict_live_flows_autoencoder(df: pd.DataFrame, save_path: str = SAVE_PATH) -> list:
    """Detect anomalies using autoencoder ensemble on live flow data.

    Args:
        df (pd.DataFrame): DataFrame containing CICFlowMeter-style features.
        save_path (str): Optional JSON output path.

    Returns:
        list: A list of dictionaries with anomaly detection results.
    """

    # === Validate Input Columns ===
    missing_cols = set(FEATURE_COLS) - set(df.columns)
    if missing_cols:
        raise ValueError(f"Missing columns in input data: {missing_cols}")

    X = df[FEATURE_COLS].copy()

    # === Load Models & Preprocessing Tools ===
    models = [
        load_model(os.path.join(MODEL_DIR, f"autoencoder_{i}.keras"), compile=False)
        for i in range(3)
    ]
    scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.joblib"))
    threshold = joblib.load(os.path.join(MODEL_DIR, "threshold.joblib"))
    inv_cov = joblib.load(os.path.join(MODEL_DIR, "inv_cov_matrix.joblib"))

    # === Scale Input ===
    X_scaled = scaler.transform(X)

    # === Reconstruction & Error Computation ===
    errors = []
    for model in models:
        recon = model.predict(X_scaled, verbose=0)
        errors.append(X_scaled - recon)

    avg_error = np.mean(errors, axis=0)

    # === Mahalanobis Distance & Anomaly Classification ===
    mahal_dists = np.array([
        distance.mahalanobis(e, np.zeros_like(e), inv_cov)
        for e in avg_error
    ])
    y_pred = (mahal_dists > threshold).astype(int)

    # === Format Results ===
    results = []
    for i, dist in enumerate(mahal_dists):
        result = {
            "flow_index": int(i),
            "mahalanobis_distance": float(dist),
            "threshold": float(threshold),
            "anomaly_detected": bool(dist > threshold),
        }
        if "Attack Type" in df.columns:
            result["true_label"] = df.iloc[i]["Attack Type"]
        results.append(result)

    # === Save to JSON ===
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    with open(save_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"✅ Saved {len(results)} predictions to {save_path}")
    return results
