from fastapi import FastAPI
from pydantic import BaseModel
import pickle
import pandas as pd

# 1. Initialize the Web API
app = FastAPI(title="SOC AI Prediction Engine")

# 2. Load the AI Brain (model.pkl) into memory
with open('model.pkl', 'rb') as file:
    model = pickle.load(file)

# 3. Define the exact JSON structure we expect from the Sensor
class NetworkFeature(BaseModel):
    timestamp: float
    source_ip: str
    destination_ip: str
    protocol: str  
    bytes: int

# 4. Create the /predict endpoint
@app.post("/predict")
async def predict_traffic(feature: NetworkFeature):
    # Map protocol strings to the numbers our AI was trained on
    protocol_map = {"TCP": 6, "ICMP": 1, "UDP": 17}
    proto_num = protocol_map.get(feature.protocol.upper(), 0)

    # Format the incoming data exactly how the AI was trained to see it
    data = pd.DataFrame([{'protocol': proto_num, 'bytes': feature.bytes}])

    # Ask the AI to make a prediction (0 = Normal, 1 = Attack)
    prediction = model.predict(data)[0]

    # Ask the AI how confident it is in its guess
    confidence = model.predict_proba(data)[0].max() * 100

    result = "Normal" if prediction == 0 else "Attack"

    return {
        "source_ip": feature.source_ip,
        "destination_ip": feature.destination_ip,
        "protocol": feature.protocol,
        "prediction": result,
        "confidence": f"{confidence:.2f}%"
    }
