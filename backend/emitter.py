import asyncio
import socketio

from sio_instance import sio

# Sample anomaly data (replace with your full dataset)


anomalies = [
  {
    "index": 49,
    "anomaly_detected": True,
    "True_label": "Brute Force",
    "predicted_label": "Brute Force",
    "confidence": 1.0,
    "class_probabilities": {
      "BENIGN": 0.0,
      "Brute Force": 1.0,
      "DDoS": 0.0,
      "DoS": 0.0,
      "Port Scan": 0.0,
      "Web Attack": 0.0
    }
  },
  {
    "index": 62,
    "anomaly_detected": True,
    "True_label": "Brute Force",
    "predicted_label": "Brute Force",
    "confidence": 1.0,
    "class_probabilities": {
      "BENIGN": 0.0,
      "Brute Force": 1.0,
      "DDoS": 0.0,
      "DoS": 0.0,
      "Port Scan": 0.0,
      "Web Attack": 0.0
    }
  },
  {
    "index": 65,
    "anomaly_detected": True,
    "True_label": "Brute Force",
    "predicted_label": "Brute Force",
    "confidence": 1.0,
    "class_probabilities": {
      "BENIGN": 0.0,
      "Brute Force": 1.0,
      "DDoS": 0.0,
      "DoS": 0.0,
      "Port Scan": 0.0,
      "Web Attack": 0.0
    }
  },
  {
    "index": 74,
    "anomaly_detected": True,
    "True_label": "Brute Force",
    "predicted_label": "Brute Force",
    "confidence": 1.0,
    "class_probabilities": {
      "BENIGN": 0.0,
      "Brute Force": 1.0,
      "DDoS": 0.0,
      "DoS": 0.0,
      "Port Scan": 0.0,
      "Web Attack": 0.0
    }
  },
  {
    "index": 101,
    "anomaly_detected": True,
    "True_label": "Brute Force",
    "predicted_label": "Brute Force",
    "confidence": 1.0,
    "class_probabilities": {
      "BENIGN": 0.0,
      "Brute Force": 1.0,
      "DDoS": 0.0,
      "DoS": 0.0,
      "Port Scan": 0.0,
      "Web Attack": 0.0
    }
  },
  {
    "index": 108,
    "anomaly_detected": True,
    "True_label": "Brute Force",
    "predicted_label": "Brute Force",
    "confidence": 1.0,
    "class_probabilities": {
      "BENIGN": 0.0,
      "Brute Force": 1.0,
      "DDoS": 0.0,
      "DoS": 0.0,
      "Port Scan": 0.0,
      "Web Attack": 0.0
    }
  },
  {
    "index": 120,
    "anomaly_detected": True,
    "True_label": "Brute Force",
    "predicted_label": "Brute Force",
    "confidence": 1.0,
    "class_probabilities": {
      "BENIGN": 0.0,
      "Brute Force": 1.0,
      "DDoS": 0.0,
      "DoS": 0.0,
      "Port Scan": 0.0,
      "Web Attack": 0.0
    }
  },
  {
    "index": 124,
    "anomaly_detected": True,
    "True_label": "Brute Force",
    "predicted_label": "Brute Force",
    "confidence": 1.0,
    "class_probabilities": {
      "BENIGN": 0.0,
      "Brute Force": 1.0,
      "DDoS": 0.0,
      "DoS": 0.0,
      "Port Scan": 0.0,
      "Web Attack": 0.0
    }
  },
  {
    "index": 137,
    "anomaly_detected": True,
    "True_label": "Brute Force",
    "predicted_label": "Brute Force",
    "confidence": 1.0,
    "class_probabilities": {
      "BENIGN": 0.0,
      "Brute Force": 1.0,
      "DDoS": 0.0,
      "DoS": 0.0,
      "Port Scan": 0.0,
      "Web Attack": 0.0
    }
  },
  {
    "index": 148,
    "anomaly_detected": True,
    "True_label": "Brute Force",
    "predicted_label": "Brute Force",
    "confidence": 1.0,
    "class_probabilities": {
      "BENIGN": 0.0,
      "Brute Force": 1.0,
      "DDoS": 0.0,
      "DoS": 0.0,
      "Port Scan": 0.0,
      "Web Attack": 0.0
    }
  },
  {
    "index": 179,
    "anomaly_detected": True,
    "True_label": "Brute Force",
    "predicted_label": "Brute Force",
    "confidence": 1.0,
    "class_probabilities": {
      "BENIGN": 0.0,
      "Brute Force": 1.0,
      "DDoS": 0.0,
      "DoS": 0.0,
      "Port Scan": 0.0,
      "Web Attack": 0.0
    }
  },
  {
    "index": 184,
    "anomaly_detected": True,
    "True_label": "Brute Force",
    "predicted_label": "Brute Force",
    "confidence": 1.0,
    "class_probabilities": {
      "BENIGN": 0.0,
      "Brute Force": 1.0,
      "DDoS": 0.0,
      "DoS": 0.0,
      "Port Scan": 0.0,
      "Web Attack": 0.0
    }
  },
  {
    "index": 198,
    "anomaly_detected": True,
    "True_label": "Brute Force",
    "predicted_label": "Brute Force",
    "confidence": 1.0,
    "class_probabilities": {
      "BENIGN": 0.0,
      "Brute Force": 1.0,
      "DDoS": 0.0,
      "DoS": 0.0,
      "Port Scan": 0.0,
      "Web Attack": 0.0
    }
  },
  {
    "index": 199,
    "anomaly_detected": True,
    "True_label": "Brute Force",
    "predicted_label": "Brute Force",
    "confidence": 1.0,
    "class_probabilities": {
      "BENIGN": 0.0,
      "Brute Force": 1.0,
      "DDoS": 0.0,
      "DoS": 0.0,
      "Port Scan": 0.0,
      "Web Attack": 0.0
    }
  },
  {
    "index": 206,
    "anomaly_detected": True,
    "True_label": "Brute Force",
    "predicted_label": "Brute Force",
    "confidence": 1.0,
    "class_probabilities": {
      "BENIGN": 0.0,
      "Brute Force": 1.0,
      "DDoS": 0.0,
      "DoS": 0.0,
      "Port Scan": 0.0,
      "Web Attack": 0.0
    }
  },
  {
    "index": 244,
    "anomaly_detected": True,
    "True_label": "Brute Force",
    "predicted_label": "Brute Force",
    "confidence": 1.0,
    "class_probabilities": {
      "BENIGN": 0.0,
      "Brute Force": 1.0,
      "DDoS": 0.0,
      "DoS": 0.0,
      "Port Scan": 0.0,
      "Web Attack": 0.0
    }
  },
  {
    "index": 254,
    "anomaly_detected": True,
    "True_label": "Brute Force",
    "predicted_label": "Brute Force",
    "confidence": 1.0,
    "class_probabilities": {
      "BENIGN": 0.0,
      "Brute Force": 1.0,
      "DDoS": 0.0,
      "DoS": 0.0,
      "Port Scan": 0.0,
      "Web Attack": 0.0
    }
  },
  {
    "index": 264,
    "anomaly_detected": True,
    "True_label": "Brute Force",
    "predicted_label": "Brute Force",
    "confidence": 1.0,
    "class_probabilities": {
      "BENIGN": 0.0,
      "Brute Force": 1.0,
      "DDoS": 0.0,
      "DoS": 0.0,
      "Port Scan": 0.0,
      "Web Attack": 0.0
    }
  },
  {
    "index": 278,
    "anomaly_detected": True,
    "True_label": "Brute Force",
    "predicted_label": "Brute Force",
    "confidence": 1.0,
    "class_probabilities": {
      "BENIGN": 0.0,
      "Brute Force": 1.0,
      "DDoS": 0.0,
      "DoS": 0.0,
      "Port Scan": 0.0,
      "Web Attack": 0.0
    }
  },
  {
    "index": 280,
    "anomaly_detected": True,
    "True_label": "Brute Force",
    "predicted_label": "Brute Force",
    "confidence": 1.0,
    "class_probabilities": {
      "BENIGN": 0.0,
      "Brute Force": 1.0,
      "DDoS": 0.0,
      "DoS": 0.0,
      "Port Scan": 0.0,
      "Web Attack": 0.0
    }
  }
]

# Function to send one record every 30 seconds
async def start_anomaly_emission():
    await sio.sleep(2)  # Optional delay before starting
    for record in anomalies:
        await sio.emit("anomaly_record", record)
        print(f"Sent record: {record}")
        await asyncio.sleep(30)

# When a client connects, start sending data
