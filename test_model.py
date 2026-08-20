import pickle
import pandas as pd

FEATURE_COLUMNS = [
    'flow_duration', 'packets_per_second', 'bytes_per_second',
    'avg_packet_size', 'unique_dst_ports', 'syn_ratio',
    'iat_mean', 'protocol_num'
]

LABELS = {0: "Normal", 1: "PortScan", 2: "DoS", 3: "BruteForce"}

print("Loading model_flow.pkl...")
with open('model_flow.pkl', 'rb') as f:
    model = pickle.load(f)

# Realistic 2-second window vectors based on your network topology
scenarios = [
    # name,             [duration, pps,   bps,    size, ports, syn,   iat,    proto]
    ("Nmap Default",    [2.0,      1500,  105000, 70,   800,   0.95,  0.001,  6]),
    ("Nmap --max-rate40",[2.0,      40,    2800,  70,   80,    0.95,  0.025,  6]),
    ("Nmap Stealth",    [2.0,      10,    700,    70,   20,    0.90,  0.100,  6]),
    ("hping3 SYN flood",[2.0,      3000,  180000, 60,   1,     1.00,  0.0003, 6]),
    ("hping3 UDP flood",[2.0,      3000,  240000, 80,   1,     0.00,  0.0003, 17]),
    ("Hydra SSH",       [10.0,     60,    24000,  400,  1,     0.45,  0.300,  6]),
    ("Normal Download", [5.0,      200,   200000, 1000, 1,     0.25,  0.050,  6]),
    ("Normal Browse",   [5.0,      30,    30000,  1000, 2,     0.20,  0.150,  6]),
]

print(f"\n{'Scenario':<20} {'Prediction':<12} {'Confidence':>10} {'Top Feature':<15}")
print("-" * 65)

for name, vec in scenarios:
    df = pd.DataFrame([vec], columns=FEATURE_COLUMNS)
    pred_idx = int(model.predict(df)[0])
    proba = model.predict_proba(df)[0].max() * 100

    # Which feature changed most from the "Normal" baseline?
    print(f"{name:<20} {LABELS[pred_idx]:<12} {proba:>9.1f}%")

print("\nIf Nmap scenarios are NOT 'PortScan', the model is still broken.")
print("If they ARE 'PortScan', restart the systemd service to deploy.")
