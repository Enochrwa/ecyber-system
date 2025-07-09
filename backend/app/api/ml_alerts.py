from fastapi import Request, APIRouter
from fastapi.responses import JSONResponse
import json
import os
import asyncio
from main import sio

router = APIRouter()

PREDICTIONS_PATHS = {
    "Port Scan": "trained_ml/ML/predictions/portscan.json",
    "Brute Force": "trained_ml/ML/predictions/bruteforce.json",
    "Web Attack": "trained_ml/ML/predictions/webattack.json",
    "DDoS": "trained_ml/ML/predictions/ddos.json",
    "DoS": "trained_ml/ML/predictions/dos.json",
}

@router.post("/alert")
async def kali_linux(request: Request):
    try:
        data = await request.json()
        attack_type = data.get("type")
        src_ip = data.get("source")
        dst_ip = data.get("destination")

        if attack_type in PREDICTIONS_PATHS:
            pred_path = PREDICTIONS_PATHS[attack_type]
            if os.path.exists(pred_path):
                with open(pred_path, "r") as f:
                    predictions = json.load(f)

                # Build all in one go
                combined_batch = [
                    {
                        "type": attack_type,
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "prediction": record,
                    }
                    for record in predictions
                ]

                # Emit all at once
                # Add timestamp to each record
                from datetime import datetime
                timestamp = datetime.utcnow().isoformat()
                combined_batch_with_timestamp = [
                    {**item, "timestamp": timestamp} for item in combined_batch
                ]
                await sio.emit("new_ml_alert", combined_batch_with_timestamp)

                return JSONResponse(
                    content={"sta2tus": "ok", "message": "Batch of predictions sent."},
                    status_code=200,
                )
            else:
                return JSONResponse(
                    content={"status": "error", "message": f"Prediction file for {attack_type} not found."},
                    status_code=404,
                )
        else:
            return JSONResponse(
                content={"status": "error", "message": f"Unknown attack type: {attack_type}"},
                status_code=400,
            )

    except Exception as e:
        print(f"[ERROR] {e}")
        return JSONResponse(
            content={"status": "error", "message": str(e)},
            status_code=500,
        )
