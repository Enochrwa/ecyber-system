import joblib
import json
import numpy as np
import pandas as pd
import logging

from lightgbm import Booster
from tensorflow.keras.models import load_model
from sniff import prepare_input_for_prediction, process_flows

# ─── Logging Config ─────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# ─── Load Models & Artifacts ────────────────────────────────
logger.info("Loading models and artifacts...")


brute_force = joblib.load("trained_models/train/models/Brute_Force/model.pkl.gz")
brute_force_scaler = joblib.load("trained_models/train/models/Brute_Force/scaler.pkl.gz")
port_scan_scaler = joblib.load("trained_models/train/models/Port_Scan/scaler.pkl.gz")
port_scan = joblib.load("trained_models/train/models/Port_Scan/model.pkl.gz")
ddos = joblib.load("trained_models/train/models/DDoS/model.pkl.gz")
ddos_scaler = joblib.load("trained_models/train/models/DDoS/scaler.pkl.gz")
dos = joblib.load("trained_models/train/models/DoS/model.pkl.gz")
dos_scaler = joblib.load("trained_models/train/models/DoS/scaler.pkl.gz")
web_attack = joblib.load("trained_models/train/models/Web_Attack/model.pkl.gz")
web_attack_scaler = joblib.load("trained_models/train/models/Web_Attack/scaler.pkl.gz")


random_forest = joblib.load("trained_models/multiclass/results/best_model_random_forest.pkl")
random_forest_scaler = joblcib.load("trained_models/multiclass/results/scaler.pkl")

# ─── Example Usage ──────────────────────────────────────────
# if __name__ == "__main__":
#     try:
#         raw = pd.read_csv("port_scan_features.csv")
#         flows = process_flows(raw)
#         vectors = prepare_input_for_prediction(flows)
#         X_scaled = port_scan_scaler.fit_transform(vectors)
#         results = port_scan.predict(X_scaled)
        
#         print(f"Results: {results}")
#     except Exception as e:
#         logger.error(f"Prediction pipeline failed: {e}")
