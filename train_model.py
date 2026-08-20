import pandas as pd
import numpy as np
import random
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import pickle

print("=" * 70)
print("  SOC-AI: Flow Model Training v3")
print("  PPS is IDENTICAL across classes -> model FORCED to use ports + syn")
print("=" * 70)
print()

np.random.seed(42)
random.seed(42)

FEATURE_COLUMNS = [
    'flow_duration',
    'packets_per_second',
    'bytes_per_second',
    'avg_packet_size',
    'unique_dst_ports',
    'syn_ratio',
    'iat_mean',
    'protocol_num'
]

# Shared PPS distribution: makes speed information-theoretically useless alone
def random_pps():
    """Return PPS from a distribution shared by Normal, PortScan, and DoS."""
    return np.random.uniform(10, 5000)

# =============================================================================
# NORMAL TRAFFIC
# =============================================================================
# Signature: FEW ports (1-4), LOW syn_ratio (0.05-0.35), LARGE packets
def generate_normal(n=2000):
    data = []
    for _ in range(n):
        duration = np.random.uniform(1.0, 10.0)
        pps = random_pps()                      # SAME distribution as attacks
        avg_size = np.random.uniform(200, 1500) # Normal payloads are large
        bps = pps * avg_size * np.random.uniform(0.8, 1.2)

        unique_ports = random.randint(1, 4)     # Very few ports
        syn_ratio = np.random.uniform(0.05, 0.35)
        iat_mean = np.random.uniform(0.01, 0.3)
        proto = random.choice([6, 17])

        data.append([duration, pps, bps, avg_size, unique_ports, syn_ratio, iat_mean, proto, 0])
    return data

# =============================================================================
# PORT SCAN
# =============================================================================
# Signature: MANY ports (10-1000), MODERATE/HIGH syn_ratio, TINY packets
# PPS is IDENTICAL to Normal and DoS -> model cannot use speed.
def generate_portscan(n=2000):
    data = []
    for _ in range(n):
        duration = np.random.uniform(0.5, 5.0)
        pps = random_pps()                      # SAME distribution
        avg_size = np.random.uniform(40, 100)   # SYN probes are tiny
        bps = pps * avg_size * np.random.uniform(0.8, 1.2)

        # THE definitive signature: many unique destination ports
        unique_ports = random.randint(10, 1000)
        # Nmap -sS sends mostly SYNs; RST replies from target go to reverse flow
        # so attacker->target flow is almost pure SYNs (~0.9+).
        # We use 0.4-0.95 to cover edge cases and stealth scans.
        syn_ratio = np.random.uniform(0.4, 0.95)
        iat_mean = np.random.uniform(0.0005, 0.05)
        proto = 6

        data.append([duration, pps, bps, avg_size, unique_ports, syn_ratio, iat_mean, proto, 1])
    return data

# =============================================================================
# DoS / DDoS
# =============================================================================
# Signature: FEW ports (1-2), VERY HIGH or VERY LOW syn_ratio, variable size
# PPS is IDENTICAL to Normal and PortScan.
def generate_dos(n=2000):
    data = []
    for _ in range(n):
        duration = np.random.uniform(1.0, 10.0)
        pps = random_pps()                      # SAME distribution
        avg_size = np.random.uniform(60, 1500)  # DoS packets vary in size
        bps = pps * avg_size * np.random.uniform(0.8, 1.2)

        # THE definitive signature: targeted (1-2 ports)
        unique_ports = random.randint(1, 2)

        # TCP SYN flood (high syn) OR UDP flood (near-zero syn)
        if random.random() > 0.5:
            syn_ratio = np.random.uniform(0.7, 1.0)  # Pure SYN flood
            proto = 6
        else:
            syn_ratio = np.random.uniform(0.0, 0.1)  # UDP flood
            proto = 17

        iat_mean = np.random.uniform(0.0001, 0.005)

        data.append([duration, pps, bps, avg_size, unique_ports, syn_ratio, iat_mean, proto, 2])
    return data

# =============================================================================
# BRUTE FORCE
# =============================================================================
# Signature: EXACTLY 1 port, moderate syn_ratio, methodical timing
def generate_bruteforce(n=2000):
    data = []
    for _ in range(n):
        duration = np.random.uniform(5.0, 30.0)
        pps = np.random.uniform(5, 300)         # Can overlap with slow traffic
        avg_size = np.random.uniform(100, 500)
        bps = pps * avg_size * np.random.uniform(0.8, 1.2)

        unique_ports = 1
        syn_ratio = np.random.uniform(0.25, 0.55)
        iat_mean = np.random.uniform(0.05, 1.0)
        proto = 6

        data.append([duration, pps, bps, avg_size, unique_ports, syn_ratio, iat_mean, proto, 3])
    return data

# =============================================================================
# BUILD & SHUFFLE DATASET
# =============================================================================
print("1. Generating Normal...")
normal = generate_normal(2000)

print("2. Generating PortScan (PPS identical to Normal/DoS)...")
portscan = generate_portscan(2000)

print("3. Generating DoS (PPS identical to Normal/PortScan)...")
dos = generate_dos(2000)

print("4. Generating BruteForce...")
bruteforce = generate_bruteforce(2000)

all_data = normal + portscan + dos + bruteforce
random.shuffle(all_data)

df = pd.DataFrame(all_data, columns=FEATURE_COLUMNS + ['label'])
X = df[FEATURE_COLUMNS]
y = df['label']

print(f"\n--- Dataset ---")
print(f"Total: {len(df)} | Class distribution:\n{df['label'].value_counts().sort_index()}")
print("  0=Normal | 1=PortScan | 2=DoS | 3=BruteForce")

# Prove PPS is identical across classes
print(f"\n--- PPS Statistics by Class (should be nearly identical) ---")
for lbl, name in [(0, "Normal"), (1, "PortScan"), (2, "DoS"), (3, "BruteForce")]:
    subset = df[df['label'] == lbl]['packets_per_second']
    print(f"  {name:12s}: mean={subset.mean():8.1f}  std={subset.std():8.1f}")

# =============================================================================
# TRAIN
# =============================================================================
print(f"\n5. Training Random Forest (200 trees)...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)

# =============================================================================
# EVALUATE
# =============================================================================
print("6. Evaluating...")
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)

print(f"\n--> Accuracy: {accuracy * 100:.2f}%")
print(classification_report(
    y_test, predictions,
    target_names=["Normal", "PortScan", "DoS", "BruteForce"]
))

# =============================================================================
# FEATURE IMPORTANCES
# =============================================================================
print("\n--- Feature Importances (Top → Bottom) ---")
importances = pd.Series(model.feature_importances_, index=FEATURE_COLUMNS)
print(importances.sort_values(ascending=False).to_string())
print("\nEXPECTED: unique_dst_ports and syn_ratio at the very top.")
print("If packets_per_second is still #1, the distributions did not overlap enough.")

# =============================================================================
# QUICK SANITY CHECK ON SYNTHETIC VECTORS
# =============================================================================
print("\n--- Sanity Check: Synthetic Vectors ---")
test_vectors = [
    ("Fast Nmap",   [2.0, 1500, 105000, 70,  800, 0.95, 0.001,  6]),
    ("Slow Nmap",   [2.0,   40,   2800, 70,   80, 0.95, 0.025,  6]),
    ("DoS SYN",     [2.0, 1500,  90000, 60,    1, 1.00, 0.0005, 6]),
    ("DoS UDP",     [2.0, 1500, 120000, 80,    1, 0.00, 0.0005, 17]),
    ("Normal HTTP", [5.0,  150, 150000, 1000,  2, 0.20, 0.100,  6]),
    ("Brute SSH",   [10.,   50,  20000, 400,   1, 0.40, 0.500,  6]),
]

labels = {0: "Normal", 1: "PortScan", 2: "DoS", 3: "BruteForce"}
for name, vec in test_vectors:
    pred = model.predict([vec])[0]
    proba = model.predict_proba([vec])[0].max() * 100
    print(f"  {name:15s} -> {labels[pred]:10s} ({proba:.1f}%)")

# =============================================================================
# SAVE
# =============================================================================
print("\n7. Saving model_flow.pkl...")
with open('model_flow.pkl', 'wb') as file:
    pickle.dump(model, file)

print("=" * 70)
print("  DONE. Run 'sudo systemctl restart soc-ai' to load the new model.")
print("=" * 70)
