import joblib
import numpy as np
import pandas as pd
from scipy.spatial import distance
from tensorflow.keras.models import load_model
from sniff import prepare_input_for_prediction, process_flows

# === Load Models ===
models = [
    load_model("trained_models/autoencoder_ensemble1/20250705_103912/autoencoder_0.keras", compile=False),
    load_model("trained_models/autoencoder_ensemble1/20250705_103912/autoencoder_1.keras", compile=False),
    load_model("trained_models/autoencoder_ensemble1/20250705_103912/autoencoder_2.keras", compile=False)
]

# === Load Scaler, Threshold, Inverse Covariance Matrix ===
scaler = joblib.load("trained_models/autoencoder_ensemble1/20250705_103912/scaler.joblib")
threshold = joblib.load("trained_models/autoencoder_ensemble1/20250705_103912/threshold.joblib")
inv_cov = joblib.load("trained_models/autoencoder_ensemble1/20250705_103912/inv_cov_matrix.joblib")

# === Load and Process Data ===
df = pd.read_csv("normal_features.csv")
flows = process_flows(raw_df=df)
X_input = prepare_input_for_prediction(flows).astype(np.float32)

# === Scale Input ===
X_scaled = scaler.transform(X_input)

# === Predict and Compute Errors ===
errors = []
for model in models:
    recon = model.predict(X_scaled, verbose=0)
    err = X_scaled - recon
    errors.append(err)

# === Average Error and Compute Mahalanobis Distance ===
avg_err = np.mean(errors, axis=0)
mahal_dists = np.array([
    distance.mahalanobis(e, np.zeros_like(e), inv_cov)
    for e in avg_err
])

# === Final Prediction ===
y_pred = (mahal_dists > threshold).astype(int)  # 1 = attack, 0 = benign
print(y_pred)
