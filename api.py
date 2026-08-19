from fastapi import FastAPI
from pydantic import BaseModel
import pickle
import pandas as pd
import sqlite3

app = FastAPI(title="SOC AI Prediction Engine")

# 1. Load the AI Brain
with open('model.pkl', 'rb') as file:
    model = pickle.load(file)

# 2. Set up the SQLite Database
conn = sqlite3.connect('soc_alerts.db', check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS alerts
                  (timestamp REAL, source_ip TEXT, destination_ip TEXT, protocol TEXT, prediction TEXT, confidence TEXT)''')
conn.commit()

class NetworkFeature(BaseModel):
    timestamp: float
    source_ip: str
    destination_ip: str
    protocol: str  
    bytes: int

@app.post("/predict")
async def predict_traffic(feature: NetworkFeature):
    protocol_map = {"TCP": 6, "ICMP": 1, "UDP": 17}
    proto_num = protocol_map.get(feature.protocol.upper(), 0)

    data = pd.DataFrame([{'protocol': proto_num, 'bytes': feature.bytes}])
    prediction = model.predict(data)[0]
    confidence = model.predict_proba(data)[0].max() * 100
    result = "Normal" if prediction == 0 else "Attack"

    # 3. Save the prediction to the database!
    cursor.execute("INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?)",
                   (feature.timestamp, feature.source_ip, feature.destination_ip, feature.protocol, result, f"{confidence:.2f}%"))
    conn.commit()

    return {
        "source_ip": feature.source_ip,
        "destination_ip": feature.destination_ip,
        "protocol": feature.protocol,
        "prediction": result,
        "confidence": f"{confidence:.2f}%"
    }

@app.get("/api/alerts")
def get_alerts():
    import sqlite3
    conn = sqlite3.connect("soc_alerts.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 100;")
    rows = cursor.fetchall()
    conn.close()
    return [dict(ix) for ix in rows]
