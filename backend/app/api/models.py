from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import pathlib
import json
from datetime import datetime
import os
import logging

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


router = APIRouter()


# Define Pydantic model for the response
class ModelInfo(BaseModel):
    id: str
    name: str
    type: str  # Algorithm type e.g. XGBoost
    description: str
    accuracy: Optional[float] = None
    f1_score: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    auc: Optional[float] = None
    confusion_matrix_data: Optional[List[Dict[str, Any]]] = None
    lastTrained: Optional[str] = None  # ISO datetime string
    features: List[str] = []
    model_file: str  # Filename
    scaler_file: str  # Filename
    metadata_file: str  # Filename
    status: str = "active"  # Default status


# Define paths to model directories
CLASSIFIER_MODELS_METRICS_DIR = (
    pathlib.Path(__file__).resolve().parent.parent.parent
    / "ml"
    / "models"
    / "eCyber_classifier_models"
)
ANOMALY_MODELS_DIR = (
    pathlib.Path(__file__).resolve().parent.parent.parent
    / "ml"
    / "models"
    / "eCyber_anomaly_isolation"
)


def get_file_mod_time(file_path: pathlib.Path) -> Optional[str]:
    """Gets the last modification time of a file as an ISO string, or None if not found."""
    try:
        mod_timestamp = os.path.getmtime(file_path)
        return datetime.fromtimestamp(mod_timestamp).isoformat() + "Z"
    except FileNotFoundError:

        return None
    except Exception as e:
        logger.error(f"Error getting modification time for {file_path}: {e}")
        return None


@router.get("/list", response_model=List[ModelInfo])
async def list_models():
    """
    Lists available ML models and their metadata by scanning specific model directories.
    """
    model_infos: List[ModelInfo] = []

    # Process Classifier Models
    if (
        CLASSIFIER_MODELS_METRICS_DIR.exists()
        and CLASSIFIER_MODELS_METRICS_DIR.is_dir()
    ):
        for model_dir in CLASSIFIER_MODELS_METRICS_DIR.iterdir():
            if model_dir.is_dir():
                model_name_from_dir = model_dir.name
                model_id = model_name_from_dir  # Use directory name as ID

                metrics_json_path = model_dir / "metrics.json"
                training_json_path = model_dir / "training.json"
                model_pkl_path = model_dir / "model.pkl.gz"
                scaler_pkl_path = model_dir / "scaler.pkl.gz"

                # Initialize defaults
                accuracy, f1_score, precision, recall, auc, confusion_matrix_data = (
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                algorithm, features_list, last_trained_str = "Unknown", [], None
                description = f"Machine learning model for {model_name_from_dir.replace('_', ' ').title()} analysis."
                display_name = model_name_from_dir.replace("_", " ").title()
                metadata_filename = "metrics.json"

                if not metrics_json_path.exists():
    
                    continue  # Essential metrics are missing

                try:
                    with open(metrics_json_path, "r", encoding="utf-8") as f:
                        metrics_data = json.load(f)
    

                    accuracy = metrics_data.get("accuracy")
                    f1_score = metrics_data.get("f1")
                    precision = metrics_data.get("precision")
                    recall = metrics_data.get("recall")
                    auc = metrics_data.get("auc")
                    raw_cm = metrics_data.get("confusion_matrix")
                    if isinstance(raw_cm, list) and all(
                        isinstance(row, list) for row in raw_cm
                    ):
                        confusion_matrix_data = [
                            {"label": f"Actual Class {i}", "values": row_values}
                            for i, row_values in enumerate(raw_cm)
                        ]
                except json.JSONDecodeError:
            
                    continue  # Skip if metrics JSON is unreadable
                except Exception as e:
                    continue

                if training_json_path.exists():
                    try:
                        with open(training_json_path, "r", encoding="utf-8") as f:
                            training_data = json.load(f)
                        algorithm = training_data.get("algorithm", algorithm)
                        features_list = training_data.get("features", features_list)
                        if isinstance(features_list, str):
                            features_list = [
                                f.strip() for f in features_list.split(",") if f.strip()
                            ]
                        last_trained_str = training_data.get(
                            "training_date", last_trained_str
                        )
                        # Potentially override display_name or description if present in training.json
                        display_name = training_data.get("name", display_name)
                        description = training_data.get("description", description)
                    except json.JSONDecodeError:
                        pass
                    except Exception as e:
                        pass

                if not last_trained_str and model_pkl_path.exists():
                    last_trained_str = get_file_mod_time(model_pkl_path)

                model_info = ModelInfo(
                    id=model_id,
                    name=display_name,
                    type=algorithm,
                    description=description,
                    accuracy=float(accuracy) if accuracy is not None else None,
                    f1_score=f1_score,
                    precision=precision,
                    recall=recall,
                    auc=auc,
                    confusion_matrix_data=confusion_matrix_data,
                    lastTrained=last_trained_str,
                    features=features_list,
                    model_file="model.pkl.gz" if model_pkl_path.exists() else "N/A",
                    scaler_file="scaler.pkl.gz" if scaler_pkl_path.exists() else "N/A",
                    metadata_file=metadata_filename,  # primarily metrics.json
                    status="active",
                )
                model_infos.append(model_info)
                
                
    # Process Anomaly Isolation Model
    if ANOMALY_MODELS_DIR.exists() and ANOMALY_MODELS_DIR.is_dir():
        # logger.info(f"Scanning for anomaly model in: {ANOMALY_MODELS_DIR}")
        anomaly_meta_path = ANOMALY_MODELS_DIR / "anomaly_meta.json"
        model_pkl_path = ANOMALY_MODELS_DIR / "anomaly_model.pkl.gz"
        scaler_pkl_path = ANOMALY_MODELS_DIR / "anomaly_scaler.pkl.gz"

        model_id = ANOMALY_MODELS_DIR.name
        display_name = model_id.replace("_", " ").title()
        description = f"Machine learning model for {display_name} analysis."
        algorithm, features_list, last_trained_str, accuracy = "Unknown", [], None, None
        metadata_filename = "anomaly_meta.json"

        if anomaly_meta_path.exists():
            try:
                with open(anomaly_meta_path, "r", encoding="utf-8") as f:
                    meta_data = json.load(f)
    

                algorithm = meta_data.get("algorithm", algorithm)
                features_list = meta_data.get("features", features_list)
                if isinstance(features_list, str):
                    features_list = [
                        f.strip() for f in features_list.split(",") if f.strip()
                    ]
                last_trained_str = meta_data.get("training_date", last_trained_str)
                accuracy = meta_data.get(
                    "best_f1_score", meta_data.get("accuracy")
                )  # Use threshold as accuracy
                display_name = meta_data.get("name", display_name)
                description = meta_data.get("description", description)

            except json.JSONDecodeError:
               pass
            except Exception as e:
               pass

        if not last_trained_str and model_pkl_path.exists():
            last_trained_str = get_file_mod_time(model_pkl_path)

        model_info = ModelInfo(
            id=model_id,
            name=display_name,
            type=algorithm,
            description=description,
            accuracy=float(accuracy) if accuracy is not None else None,
            f1_score=None,  # Typically not applicable or not provided for basic anomaly
            precision=None,
            recall=None,
            auc=None,
            confusion_matrix_data=None,
            lastTrained=last_trained_str,
            features=features_list,
            model_file="anomaly_model.pkl.gz" if model_pkl_path.exists() else "N/A",
            scaler_file="anomaly_scaler.pkl.gz" if scaler_pkl_path.exists() else "N/A",
            metadata_file=metadata_filename,
            status="active",
        )
        model_infos.append(model_info)

    return model_infos


PREDICTIONS_PATH = (
    pathlib.Path(__file__).resolve().parent.parent.parent
    / "trained_ml"
    / "ML"
    / "predictions"
)

@router.get("/predictions", summary="Get ML model predictions", description="Retrieves stored ML model predictions. Can be filtered by prediction type.")
async def get_ml_predictions(type: str | None = None):
    if not PREDICTIONS_PATH.exists() or not PREDICTIONS_PATH.is_dir():
        raise HTTPException(status_code=404, detail="Predictions directory not found.")

    if type:
        # Sanitize type to prevent directory traversal
        safe_type_name = "".join(c for c in type if c.isalnum() or c in ['_', '-']).lower()
        prediction_file_path = PREDICTIONS_PATH / f"{safe_type_name}.json"
        
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
            raise HTTPException(status_code=500, detail=f"Error reading prediction file: {str(e)}")
    
    else:
        # Load all .json prediction files
        all_predictions = {}
        has_files = False

        for prediction_file_path in PREDICTIONS_PATH.glob("*.json"):
            if prediction_file_path.is_file():
                has_files = True
                prediction_type = prediction_file_path.stem  # e.g., 'bruteforce' from 'bruteforce.json'
                try:
                    with open(prediction_file_path, 'r') as f:
                        data = json.load(f)
                    last_modified = datetime.fromtimestamp(prediction_file_path.stat().st_mtime).isoformat()
                    all_predictions[prediction_type] = {
                        "last_modified": last_modified,
                        "predictions": data
                    }
                except Exception as e:
                    all_predictions[prediction_type] = {
                        "error": f"Could not load predictions: {str(e)}"
                    }

        if not has_files:
            raise HTTPException(status_code=404, detail="No prediction files found in the directory.")

        return all_predictions
