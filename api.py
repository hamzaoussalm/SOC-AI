from fastapi import FastAPI
from pydantic import BaseModel
import pickle
import pandas as pd
import sqlite3
import os

app = FastAPI(title="SOC AI Flow Prediction Engine")

# --- 1. Load the AI Brain ---
MODEL_PATH = "model_flow.pkl"
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(
        f"Model file '{MODEL_PATH}' not found. "
        "Run 'python3 train_model.py' on the ML Node first."
    )

with open(MODEL_PATH, 'rb') as file:
    model = pickle.load(file)

# 4-class mapping
CLASS_LABELS = {
    0: "Normal",
    1: "PortScan",
    2: "DoS",
    3: "BruteForce"
}

# --- 2. Database Setup (New Table: flow_alerts) ---
DB_PATH = "soc_alerts.db"
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS flow_alerts (
    timestamp REAL,
    source_ip TEXT,
    destination_ip TEXT,
    protocol TEXT,
    prediction TEXT,
    confidence TEXT,
    flow_duration REAL,
    packets_per_second REAL,
    bytes_per_second REAL,
    avg_packet_size REAL,
    unique_dst_ports INTEGER,
    syn_ratio REAL,
    iat_mean REAL
)
''')
conn.commit()

# --- 3. Pydantic Request Model ---
class FlowFeatures(BaseModel):
    timestamp: float
    source_ip: str
    destination_ip: str
    protocol: str
    flow_duration: float
    packets_per_second: float
    bytes_per_second: float
    avg_packet_size: float
    unique_dst_ports: int
    syn_ratio: float
    iat_mean: float
    protocol_num: int

@app.post("/predict_flow")
async def predict_flow(feature: FlowFeatures):
    """
    Receive aggregated flow features from the Sensor,
    predict attack class, and log to SQLite.
    """
    # Build DataFrame with exact training column order
    data = pd.DataFrame([{
        'flow_duration': feature.flow_duration,
        'packets_per_second': feature.packets_per_second,
        'bytes_per_second': feature.bytes_per_second,
        'avg_packet_size': feature.avg_packet_size,
        'unique_dst_ports': feature.unique_dst_ports,
        'syn_ratio': feature.syn_ratio,
        'iat_mean': feature.iat_mean,
        'protocol_num': feature.protocol_num
    }])

    # Predict
    prediction_idx = int(model.predict(data)[0])
    confidence = model.predict_proba(data)[0].max() * 100
    prediction_label = CLASS_LABELS.get(prediction_idx, "Unknown")

    # Persist to database
    cursor.execute('''
        INSERT INTO flow_alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        feature.timestamp,
        feature.source_ip,
        feature.destination_ip,
        feature.protocol,
        prediction_label,
        f"{confidence:.2f}%",
        feature.flow_duration,
        feature.packets_per_second,
        feature.bytes_per_second,
        feature.avg_packet_size,
        feature.unique_dst_ports,
        feature.syn_ratio,
        feature.iat_mean
    ))
    conn.commit()

    return {
        "source_ip": feature.source_ip,
        "destination_ip": feature.destination_ip,
        "protocol": feature.protocol,
        "prediction": prediction_label,
        "confidence": f"{confidence:.2f}%",
        "packets_per_second": feature.packets_per_second,
        "unique_dst_ports": feature.unique_dst_ports,
        "syn_ratio": feature.syn_ratio
    }

@app.get("/api/alerts")
def get_alerts():
    """
    Grafana JSON endpoint.
    Returns the 100 most recent flow predictions.
    """
    conn_local = sqlite3.connect(DB_PATH)
    conn_local.row_factory = sqlite3.Row
    cur = conn_local.cursor()
    cur.execute("""
        SELECT * FROM flow_alerts
        ORDER BY timestamp DESC
        LIMIT 100;
    """)
    rows = cur.fetchall()
    conn_local.close()
    return [dict(ix) for ix in rows]

@app.get("/health")
def health_check():
    return {"status": "ok", "model_loaded": True, "model_path": MODEL_PATH}
