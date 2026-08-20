import pandas as pd
import numpy as np
import random
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import pickle

print("=" * 60)
print("  SOC-AI: Flow-Based Multi-Class Model Training")
print("=" * 60)
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

def generate_normal(n=2000):
    """Normal browsing, file transfers, DNS, etc."""
    data = []
    for _ in range(n):
        duration = np.random.uniform(1.0, 10.0)
        pps = np.random.uniform(5, 50)
        bps = np.random.uniform(500, 50000)
        avg_size = np.random.uniform(100, 1500)
        unique_ports = random.randint(1, 3)
        syn_ratio = np.random.uniform(0.1, 0.3)
        iat_mean = np.random.uniform(0.01, 0.2)
        proto = random.choice([6, 17])  # TCP or UDP
        data.append([duration, pps, bps, avg_size, unique_ports, syn_ratio, iat_mean, proto, 0])
    return data

def generate_portscan(n=2000):
    """Nmap-style TCP port scan."""
    data = []
    for _ in range(n):
        duration = np.random.uniform(0.5, 5.0)
        pps = np.random.uniform(100, 1000)
        bps = np.random.uniform(6000, 60000)
        avg_size = np.random.uniform(40, 100)  # Small SYN packets
        unique_ports = random.randint(10, 100)  # KEY SIGNATURE
        syn_ratio = np.random.uniform(0.8, 1.0)
        iat_mean = np.random.uniform(0.001, 0.01)
        proto = 6  # TCP only
        data.append([duration, pps, bps, avg_size, unique_ports, syn_ratio, iat_mean, proto, 1])
    return data

def generate_dos(n=2000):
    """DoS/DDoS flood (SYN flood or UDP flood)."""
    data = []
    for _ in range(n):
        duration = np.random.uniform(1.0, 10.0)
        pps = np.random.uniform(500, 5000)  # Extreme rate
        bps = np.random.uniform(500000, 5000000)
        avg_size = np.random.uniform(60, 1500)
        unique_ports = random.randint(1, 2)  # Targeted

        # Split: SYN flood (TCP) vs UDP flood
        if random.random() > 0.5:
            syn_ratio = np.random.uniform(0.5, 0.9)
            proto = 6
        else:
            syn_ratio = np.random.uniform(0.0, 0.05)
            proto = 17

        iat_mean = np.random.uniform(0.0001, 0.001)  # Very bursty
        data.append([duration, pps, bps, avg_size, unique_ports, syn_ratio, iat_mean, proto, 2])
    return data

def generate_bruteforce(n=2000):
    """SSH/FTP brute force."""
    data = []
    for _ in range(n):
        duration = np.random.uniform(5.0, 30.0)
        pps = np.random.uniform(10, 100)
        bps = np.random.uniform(1000, 10000)
        avg_size = np.random.uniform(100, 500)
        unique_ports = 1  # Always port 22 or 21
        syn_ratio = np.random.uniform(0.3, 0.5)
        iat_mean = np.random.uniform(0.05, 1.0)  # Methodical rhythm
        proto = 6  # TCP only
        data.append([duration, pps, bps, avg_size, unique_ports, syn_ratio, iat_mean, proto, 3])
    return data

# --- BUILD DATASET ---
import pandas as pd
import numpy as np
import random
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import pickle

print("=" * 65)
print("  SOC-AI: Flow-Based Model Training (v2 - Overlapping PPS)")
print("=" * 65)
print("""
STRATEGY:
- PPS ranges OVERLAP heavily across Normal / PortScan / DoS.
- The model CANNOT rely on speed alone.
- PortScan is defined by:  many unique ports  +  high SYN ratio.
- DoS is defined by:      few unique ports   +  extreme volume.
- Normal is defined by:   few unique ports   +  low SYN ratio.
""")
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

# =============================================================================
# NORMAL TRAFFIC
# =============================================================================
# Key signature: LOW unique_dst_ports (1-4), LOW syn_ratio (0.1-0.4)
# PPS is WIDE (5-1000) to force overlap with PortScan and DoS.
def generate_normal(n=2000):
    data = []
    for _ in range(n):
        duration = np.random.uniform(1.0, 10.0)

        # PPS overlaps with PortScan and DoS deliberately
        pps = np.random.uniform(5, 1000)

        avg_size = np.random.uniform(200, 1500)
        bps = pps * avg_size * np.random.uniform(0.8, 1.2)

        unique_ports = random.randint(1, 4)
        syn_ratio = np.random.uniform(0.1, 0.4)
        iat_mean = np.random.uniform(0.01, 0.2)
        proto = random.choice([6, 17])

        data.append([duration, pps, bps, avg_size, unique_ports, syn_ratio, iat_mean, proto, 0])
    return data

# =============================================================================
# PORT SCAN
# =============================================================================
# Key signature: HIGH unique_dst_ports (10-1000), HIGH syn_ratio (0.7-1.0)
# PPS is EXTREMELY WIDE (10-5000) so the model sees slow stealth scans,
# default Nmap scans, AND aggressive scans in the SAME class.
def generate_portscan(n=2000):
    data = []
    for _ in range(n):
        duration = np.random.uniform(0.5, 5.0)

        # Full range: from stealthy 10 PPS up to aggressive 5000 PPS
        pps = np.random.uniform(10, 5000)

        # SYN probes are tiny (40-100 bytes)
        avg_size = np.random.uniform(40, 100)
        bps = pps * avg_size * np.random.uniform(0.8, 1.2)

        # THE definitive signature: many ports touched
        unique_ports = random.randint(10, 1000)
        syn_ratio = np.random.uniform(0.7, 1.0)
        iat_mean = np.random.uniform(0.0005, 0.05)
        proto = 6  # TCP only

        data.append([duration, pps, bps, avg_size, unique_ports, syn_ratio, iat_mean, proto, 1])
    return data

# =============================================================================
# DoS / DDoS
# =============================================================================
# Key signature: LOW unique_dst_ports (1-2), HIGH volume
# PPS overlaps with PortScan (50-5000) so the model MUST look at port count.
def generate_dos(n=2000):
    data = []
    for _ in range(n):
        duration = np.random.uniform(1.0, 10.0)

        # Overlaps with PortScan heavily
        pps = np.random.uniform(50, 5000)

        # DoS packets vary in size (60-1500), unlike the tiny scan probes
        avg_size = np.random.uniform(60, 1500)
        bps = pps * avg_size * np.random.uniform(0.8, 1.2)

        # THE definitive signature: targeted (1-2 ports)
        unique_ports = random.randint(1, 2)

        # SYN flood (high syn_ratio) OR UDP flood (near-zero syn_ratio)
        if random.random() > 0.5:
            syn_ratio = np.random.uniform(0.5, 0.9)
            proto = 6
        else:
            syn_ratio = np.random.uniform(0.0, 0.05)
            proto = 17

        iat_mean = np.random.uniform(0.0001, 0.005)

        data.append([duration, pps, bps, avg_size, unique_ports, syn_ratio, iat_mean, proto, 2])
    return data

# =============================================================================
# BRUTE FORCE
# =============================================================================
# Key signature: EXACTLY 1 port (SSH/FTP), moderate syn_ratio, methodical IAT
# PPS is low (5-100) but can overlap with slow Normal or stealth PortScan.
def generate_bruteforce(n=2000):
    data = []
    for _ in range(n):
        duration = np.random.uniform(5.0, 30.0)

        pps = np.random.uniform(5, 100)
        avg_size = np.random.uniform(100, 500)
        bps = pps * avg_size * np.random.uniform(0.8, 1.2)

        unique_ports = 1
        syn_ratio = np.random.uniform(0.3, 0.6)
        iat_mean = np.random.uniform(0.05, 1.0)
        proto = 6

        data.append([duration, pps, bps, avg_size, unique_ports, syn_ratio, iat_mean, proto, 3])
    return data

# =============================================================================
# BUILD DATASET
# =============================================================================
print("1. Synthesizing Normal traffic flows...")
normal = generate_normal(2000)

print("2. Synthesizing Port Scan flows (PPS: 10-5000)...")
portscan = generate_portscan(2000)

print("3. Synthesizing DoS/DDoS flows (PPS: 50-5000)...")
dos = generate_dos(2000)

print("4. Synthesizing Brute Force flows...")
bruteforce = generate_bruteforce(2000)

all_data = normal + portscan + dos + bruteforce
random.shuffle(all_data)

df = pd.DataFrame(all_data, columns=FEATURE_COLUMNS + ['label'])
X = df[FEATURE_COLUMNS]
y = df['label']

print(f"\n--- Dataset Statistics ---")
print(f"Total samples: {len(df)}")
print(f"Class distribution:")
print(df['label'].value_counts().sort_index())
print("  0=Normal | 1=PortScan | 2=DoS | 3=BruteForce")

# Verify PPS overlap
print(f"\n--- PPS Range Verification ---")
for lbl, name in [(0, "Normal"), (1, "PortScan"), (2, "DoS"), (3, "BruteForce")]:
    subset = df[df['label'] == lbl]['packets_per_second']
    print(f"  {name:12s}: min={subset.min():8.1f}  max={subset.max():9.1f}")

# =============================================================================
# TRAIN / TEST SPLIT
# =============================================================================
print(f"\n5. Training Random Forest (100 estimators)...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)

# =============================================================================
# EVALUATION
# =============================================================================
print("6. Evaluating model...")
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)

print(f"\n--> Overall Accuracy: {accuracy * 100:.2f}%")
print("\nDetailed Classification Report:")
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
print("""
EXPECTED: unique_dst_ports and syn_ratio should be at the TOP.
If packets_per_second is still #1, the overlap was insufficient.
""")

# =============================================================================
# SAVE MODEL
# =============================================================================
print("\n7. Saving model as 'model_flow.pkl'...")
with open('model_flow.pkl', 'wb') as file:
    pickle.dump(model, file)

print("=" * 65)
print("  SUCCESS: model_flow.pkl is ready.")
print("  Restart your ML Node service to load the new brain.")
print("=" * 65)
