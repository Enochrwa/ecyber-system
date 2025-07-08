import os
import json
import joblib
import numpy as np
import pandas as pd

# Define global constants
FEATURE_COLS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Avg Fwd Bytes/Bulk", "Avg Bwd Bytes/Bulk",
    "Avg Fwd Packets/Bulk", "Avg Bwd Packets/Bulk", "Fwd Bulk Rate Avg",
    "Bwd Bulk Rate Avg", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean",
    "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
    "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Fwd URG Flags",
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std",
    "Packet Length Variance", "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
    "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "CWE Flag Count",
    "ECE Flag Count", "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size",
    "Avg Bwd Segment Size", "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward",
    "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
]

LABEL_CLASSES = ["BENIGN", "Brute Force", "DDoS", "DoS", "Port Scan", "Web Attack"]

MODEL_DIR = "trained_ml/ML/models/multiclass/results/"
MODEL_PATH = os.path.join(MODEL_DIR, "best_model_random_forest.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")


def predict_live_flows(df: pd.DataFrame, save_path: str = "predictions/live_predictions.json") -> list:
    """Predict attack classes for a live dataframe of flow features.

    Args:
        df (pd.DataFrame): A DataFrame containing CICFlowMeter-style features.
        save_path (str): Optional path to save JSON output.

    Returns:
        list: A list of prediction dictionaries.
    """

    # Validate columns
    missing = set(FEATURE_COLS) - set(df.columns)
    if missing:
        raise ValueError(f"Missing features in input DataFrame: {missing}")

    X_live = df[FEATURE_COLS]

    # Load model and scaler
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    # Scale features
    X_scaled = scaler.transform(X_live.values)

    # Predict
    y_pred_indices = model.predict(X_scaled)
    y_pred_probs = model.predict_proba(X_scaled) if hasattr(model, "predict_proba") else None

    results = []
    for i in range(len(X_live)):
        pred_index = y_pred_indices[i]
        pred_label = LABEL_CLASSES[pred_index] if pred_index < len(LABEL_CLASSES) else "Unknown"
        confidence = float(np.max(y_pred_probs[i])) if y_pred_probs is not None else None
        class_probs = (
            {LABEL_CLASSES[j]: float(y_pred_probs[i][j]) for j in range(len(LABEL_CLASSES))}
            if y_pred_probs is not None else None
        )

        results.append({
            "flow_index": int(i),
            "anomaly_detected": pred_label != "BENIGN",
            "predicted_label": pred_label,
            "confidence": confidence,
            "class_probabilities": class_probs,
        })

    # Save to JSON file
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    with open(save_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"✅ Saved {len(results)} predictions to {save_path}")
    return results
