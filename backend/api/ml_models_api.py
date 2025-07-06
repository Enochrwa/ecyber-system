import os
import json
from pathlib import Path
from datetime import datetime
from fastapi import APIRouter, HTTPException

router = APIRouter()

# Define paths to model directories
BASE_MODEL_PATH = Path("backend/ml/models")
CLASSIFIER_MODELS_PATH = BASE_MODEL_PATH / "eCyber_classifier_models"
ANOMALY_MODEL_PATH = BASE_MODEL_PATH / "eCyber_anomaly_isolation"

@router.get("/list", summary="List all ML models", description="Retrieves a list of all machine learning models with their metadata.")
async def list_models():
    models_data = []

    # Process Classifier Models
    if CLASSIFIER_MODELS_PATH.exists() and CLASSIFIER_MODELS_PATH.is_dir():
        for model_dir in CLASSIFIER_MODELS_PATH.iterdir():
            if model_dir.is_dir():
                model_name = model_dir.name
                metrics_path = model_dir / "metrics.json"
                training_path = model_dir / "training.json"
                model_file_path = model_dir / "model.pkl.gz"
                scaler_file_path = model_dir / "scaler.pkl.gz" # Assuming scaler has a standard name

                metrics_data = {}
                if metrics_path.exists():
                    with open(metrics_path, 'r') as f:
                        metrics_data = json.load(f)

                training_data = {}
                if training_path.exists():
                    with open(training_path, 'r') as f:
                        training_data = json.load(f)

                last_trained = None
                if model_file_path.exists():
                    try:
                        last_trained_timestamp = model_file_path.stat().st_mtime
                        last_trained = datetime.fromtimestamp(last_trained_timestamp).isoformat()
                    except Exception:
                        last_trained = None # Fallback if modification time cannot be read

                model_info = {
                    "id": model_name, # Assuming model_name is unique
                    "name": model_name.replace("_", " ").title(),
                    "status": "active", # Default status
                    "accuracy": metrics_data.get("accuracy"),
                    "lastTrained": last_trained,
                    "description": metrics_data.get("description", f"Classifier model: {model_name}"),
                    "type": metrics_data.get("model_type", model_name.split('_')[0].upper()), # Infer type or get from metrics
                    "features": training_data.get("features_list", []), # training.json might contain "features_list"
                    "model_file": str(model_file_path),
                    "scaler_file": str(scaler_file_path) if scaler_file_path.exists() else None,
                    "metadata_file": str(metrics_path) if metrics_path.exists() else None,
                    "auc": metrics_data.get("auc"),
                    "precision": metrics_data.get("precision"),
                    "recall": metrics_data.get("recall"),
                    "f1Score": metrics_data.get("f1_score"), # metrics.json might use "f1_score"
                    "confusionMatrixData": metrics_data.get("confusion_matrix"), # metrics.json might contain "confusion_matrix"
                    "featureImportanceData": training_data.get("feature_importance") # training.json might contain "feature_importance"
                }
                models_data.append(model_info)

    # Process Anomaly Model
    anomaly_meta_file = ANOMALY_MODEL_PATH / "anomaly_meta.json"
    anomaly_model_file = ANOMALY_MODEL_PATH / "anomaly_model.pkl" # Assuming standard name
    
    if anomaly_meta_file.exists():
        with open(anomaly_meta_file, 'r') as f:
            anomaly_meta = json.load(f)

        last_trained_anomaly = None
        if anomaly_model_file.exists():
            try:
                last_trained_timestamp = anomaly_model_file.stat().st_mtime
                last_trained_anomaly = datetime.fromtimestamp(last_trained_timestamp).isoformat()
            except Exception:
                last_trained_anomaly = None

        anomaly_model_info = {
            "id": anomaly_meta.get("model_id", "anomaly_detector"),
            "name": anomaly_meta.get("model_name", "Anomaly Detection Model"),
            "status": "active",
            "accuracy": anomaly_meta.get("accuracy"), # Or relevant performance metric
            "lastTrained": last_trained_anomaly,
            "description": anomaly_meta.get("description", "Detects anomalies in network traffic."),
            "type": anomaly_meta.get("model_type", "IsolationForest"), # Default or from meta
            "features": anomaly_meta.get("features", []),
            "model_file": str(anomaly_model_file) if anomaly_model_file.exists() else None,
            "scaler_file": None, # Anomaly models might not always have a separate scaler
            "metadata_file": str(anomaly_meta_file),
            "auc": anomaly_meta.get("auc"), # Anomaly models might have different metrics
            "precision": anomaly_meta.get("precision"),
            "recall": anomaly_meta.get("recall"),
            "f1Score": anomaly_meta.get("f1_score"),
            "confusionMatrixData": anomaly_meta.get("confusion_matrix"), # Might not be applicable or available
            "featureImportanceData": None # Typically not available for Isolation Forest
        }
        models_data.append(anomaly_model_info)
    
    if not models_data:
        # You could return a 404 if no models are found, or an empty list.
        # For now, returning an empty list.
        pass

    return models_data

PREDICTIONS_PATH = Path("backend/trained_ml/ML/predictions")

@router.get("/predictions", summary="Get ML model predictions", description="Retrieves stored ML model predictions. Can be filtered by prediction type.")
async def get_ml_predictions(type: str | None = None):
    predictions_data = {}
    
    if not PREDICTIONS_PATH.exists() or not PREDICTIONS_PATH.is_dir():
        raise HTTPException(status_code=404, detail="Predictions directory not found.")

    if type:
        # Sanitize type to prevent directory traversal
        safe_type_name = "".join(c for c in type if c.isalnum() or c in ['_', '-']).lower()
        prediction_file_name = f"random_forest_{safe_type_name}_predictions.json"
        prediction_file_path = PREDICTIONS_PATH / prediction_file_name
        
        if not prediction_file_path.exists() or not prediction_file_path.is_file():
            raise HTTPException(status_code=404, detail=f"Predictions for type '{type}' not found.")
        
        try:
            with open(prediction_file_path, 'r') as f:
                data = json.load(f)
            last_modified = datetime.fromtimestamp(prediction_file_path.stat().st_mtime).isoformat()
            return {
                "type": safe_type_name,
                "last_modified": last_modified,
                "predictions": data
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error reading prediction file for type '{type}': {str(e)}")
    else:
        # Load all JSON files in the predictions directory
        all_predictions = {}
        has_files = False
        for prediction_file_path in PREDICTIONS_PATH.glob("*.json"):
            if prediction_file_path.is_file():
                has_files = True
                file_name_parts = prediction_file_path.name.split('_')
                # Expecting format like "random_forest_bruteforce_predictions.json"
                # or "xgboost_dos_predictions.json"
                if len(file_name_parts) > 2 and file_name_parts[-1] == "predictions.json":
                    # Try to extract type, e.g., "bruteforce"
                    prediction_type = "_".join(file_name_parts[2:-1]) if len(file_name_parts) > 3 else file_name_parts[1]
                    # Fallback if parsing is tricky
                    if not prediction_type or prediction_type == "predictions.json": 
                        prediction_type = prediction_file_path.stem # filename without extension as a fallback key
                else:
                    # Fallback for unexpected names
                    prediction_type = prediction_file_path.stem

                try:
                    with open(prediction_file_path, 'r') as f:
                        data = json.load(f)
                    last_modified = datetime.fromtimestamp(prediction_file_path.stat().st_mtime).isoformat()
                    all_predictions[prediction_type] = {
                        "last_modified": last_modified,
                        "predictions": data
                    }
                except Exception as e:
                    # Log error or skip file
                    print(f"Error reading {prediction_file_path.name}: {e}") 
                    all_predictions[prediction_type] = {
                        "error": f"Could not load predictions: {str(e)}"
                    }
        
        if not has_files:
            raise HTTPException(status_code=404, detail="No prediction files found in the directory.")
            
        return all_predictions
