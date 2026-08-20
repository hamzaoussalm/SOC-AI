"""
SOC-AI: Flow Model Training v4
==============================
Fixes three live-fire misclassification bugs discovered during CloudLab testing:

  Bug 1: BruteForce (Hydra SSH) labelled as Normal
  Bug 2: Scan Backscatter (target RST replies) labelled as PortScan
  Bug 3: DoS Backscatter (target RST/ICMP replies) labelled as DoS
"""

import pandas as pd
import numpy as np
import random
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import pickle

print("=" * 70)
print("  SOC-AI: Flow Model Training v4")
print("  Backscatter-aware | 4 attack classes + 3 Normal sub-profiles")
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

# =============================================================================
# NORMAL TRAFFIC — 3 sub-profiles, all labelled 0
# =============================================================================

def generate_normal_browsing(n=1500):
    """
    Human web/DNS/email traffic.
    Signature: FEW ports, LOW syn_ratio, LARGE packets, SLOW iat (human speed).
    """
    data = []
    for _ in range(n):
        duration     = np.random.uniform(1.0, 15.0)
        pps          = np.random.uniform(10, 500)
        avg_size     = np.random.uniform(200, 1500)
        bps          = pps * avg_size * np.random.uniform(0.8, 1.2)
        unique_ports = random.randint(1, 4)
        syn_ratio    = np.random.uniform(0.05, 0.35)
        iat_mean     = np.random.uniform(0.05, 0.5)
        proto        = random.choice([6, 17])
        data.append([duration, pps, bps, avg_size, unique_ports, syn_ratio, iat_mean, proto, 0])
    return data


def generate_scan_backscatter(n=1000):
    """
    Target's RST/SYN-ACK replies to an Nmap scan.
    The sensor sees the TARGET sending to many ports on the ATTACKER.

    Key discriminators vs true PortScan:
      - syn_ratio ~ 0.0  (RST/SYN-ACK carry no pure SYN flag)
      - avg_size  ~ 40-80 bytes (bare TCP header, no payload)
    """
    data = []
    for _ in range(n):
        duration     = np.random.uniform(0.5, 5.0)
        pps          = np.random.uniform(50, 5000)
        avg_size     = np.random.uniform(40, 80)       # RST/SYN-ACK: header only
        bps          = pps * avg_size * np.random.uniform(0.8, 1.2)
        unique_ports = random.randint(10, 1000)         # Many reply ports
        syn_ratio    = np.random.uniform(0.0, 0.05)    # Near-zero: no pure SYN
        iat_mean     = np.random.uniform(0.0001, 0.005)
        proto        = 6
        data.append([duration, pps, bps, avg_size, unique_ports, syn_ratio, iat_mean, proto, 0])
    return data


def generate_dos_backscatter(n=1000):
    """
    Target's RST/ICMP-unreachable replies to a DoS flood.
    Key discriminator vs true DoS: avg_size is TINY (40-80 bytes = header only).
    """
    data = []
    for _ in range(n):
        duration     = np.random.uniform(1.0, 10.0)
        pps          = np.random.uniform(100, 5000)
        avg_size     = np.random.uniform(40, 80)       # RST/ICMP: header only <- THE KEY FIX
        bps          = pps * avg_size * np.random.uniform(0.8, 1.2)
        unique_ports = random.randint(1, 2)
        syn_ratio    = np.random.uniform(0.0, 0.05)
        iat_mean     = np.random.uniform(0.0001, 0.002)
        proto        = random.choice([6, 1])            # TCP RST or ICMP
        data.append([duration, pps, bps, avg_size, unique_ports, syn_ratio, iat_mean, proto, 0])
    return data


# =============================================================================
# PORT SCAN (label 1)
# =============================================================================

def generate_portscan(n=2000):
    """
    Attacker -> Target: pure SYN probes to many ports.
    Key discriminator vs ScanBackscatter: syn_ratio is HIGH (0.4-0.95).
    """
    data = []
    for _ in range(n):
        duration     = np.random.uniform(0.5, 5.0)
        pps          = np.random.uniform(10, 5000)
        avg_size     = np.random.uniform(40, 100)      # SYN probes are tiny
        bps          = pps * avg_size * np.random.uniform(0.8, 1.2)
        unique_ports = random.randint(10, 1000)
        syn_ratio    = np.random.uniform(0.4, 0.95)    # Mostly pure SYN packets
        iat_mean     = np.random.uniform(0.0005, 0.05)
        proto        = 6
        data.append([duration, pps, bps, avg_size, unique_ports, syn_ratio, iat_mean, proto, 1])
    return data


# =============================================================================
# DoS / DDoS (label 2)
# =============================================================================

def generate_dos(n=2000):
    """
    Attacker -> Target: volumetric flood to ONE or TWO ports.
    Key discriminator vs DoSBackscatter: avg_size is LARGER (60-1500 bytes).
    """
    data = []
    for _ in range(n):
        duration     = np.random.uniform(1.0, 10.0)
        pps          = np.random.uniform(100, 5000)
        unique_ports = random.randint(1, 2)
        iat_mean     = np.random.uniform(0.0001, 0.005)

        flood_type = random.random()
        if flood_type < 0.40:
            # TCP SYN flood (hping3 --syn)
            avg_size  = np.random.uniform(60, 120)    # SYN header: 60-74 bytes
            syn_ratio = np.random.uniform(0.7, 1.0)
            proto     = 6
        elif flood_type < 0.70:
            # UDP flood
            avg_size  = np.random.uniform(64, 1500)   # UDP carries real payload
            syn_ratio = np.random.uniform(0.0, 0.05)
            proto     = 17
        elif flood_type < 0.85:
            # ICMP ping flood
            avg_size  = np.random.uniform(64, 1500)
            syn_ratio = 0.0
            proto     = 1
        else:
            # HTTP flood
            avg_size  = np.random.uniform(200, 1500)
            syn_ratio = np.random.uniform(0.1, 0.4)
            proto     = 6

        bps = pps * avg_size * np.random.uniform(0.8, 1.2)
        data.append([duration, pps, bps, avg_size, unique_ports, syn_ratio, iat_mean, proto, 2])
    return data


# =============================================================================
# BRUTE FORCE (label 3)
# =============================================================================

def generate_bruteforce(n=2000):
    """
    Hydra / Medusa SSH or FTP brute force.
    Key discriminators vs Normal:
      - flow_duration = LONG (10-120 s)
      - unique_dst_ports = EXACTLY 1
      - avg_size = LARGE (100-600 bytes, real SSH payloads)
      - iat_mean = MODERATE (0.05-1.0 s, methodical pacing)
    """
    data = []
    for _ in range(n):
        pps          = np.random.uniform(5, 300)
        duration     = np.random.uniform(10.0, 120.0)  # Long campaigns
        avg_size     = np.random.uniform(100, 600)      # Real auth payloads
        bps          = pps * avg_size * np.random.uniform(0.8, 1.2)
        unique_ports = 1                                # Only port 22 or 21
        syn_ratio    = np.random.uniform(0.25, 0.55)   # 1 SYN per attempt
        iat_mean     = np.random.uniform(0.05, 1.0)    # Methodical pacing
        proto        = 6
        data.append([duration, pps, bps, avg_size, unique_ports, syn_ratio, iat_mean, proto, 3])
    return data


# =============================================================================
# BUILD, SHUFFLE & SPLIT
# =============================================================================

print("1. Generating Normal Browsing (1500)...")
normal_browsing  = generate_normal_browsing(1500)

print("2. Generating Scan Backscatter -> Normal (1000)...")
scan_backscatter = generate_scan_backscatter(1000)

print("3. Generating DoS Backscatter  -> Normal (1000)...")
dos_backscatter  = generate_dos_backscatter(1000)

print("4. Generating PortScan (2000)...")
portscan         = generate_portscan(2000)

print("5. Generating DoS (2000)...")
dos              = generate_dos(2000)

print("6. Generating BruteForce (2000)...")
bruteforce       = generate_bruteforce(2000)

all_data = (
    normal_browsing + scan_backscatter + dos_backscatter +
    portscan + dos + bruteforce
)
random.shuffle(all_data)

df = pd.DataFrame(all_data, columns=FEATURE_COLUMNS + ['label'])
X  = df[FEATURE_COLUMNS]
y  = df['label']

print(f"\n--- Dataset Summary ---")
print(f"Total samples: {len(df)}")
label_map = {0: "Normal (all sub-profiles)", 1: "PortScan", 2: "DoS", 3: "BruteForce"}
for lbl in sorted(df['label'].unique()):
    count = (df['label'] == lbl).sum()
    print(f"  {lbl} = {label_map[lbl]}: {count} samples")

# =============================================================================
# TRAIN
# =============================================================================

print(f"\n7. Training Random Forest (200 trees)...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

model = RandomForestClassifier(
    n_estimators=200,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)

# =============================================================================
# EVALUATE
# =============================================================================

print("8. Evaluating on held-out test set...")
predictions = model.predict(X_test)
accuracy    = accuracy_score(y_test, predictions)

print(f"\n--> Accuracy: {accuracy * 100:.2f}%")
print(classification_report(
    y_test, predictions,
    target_names=["Normal", "PortScan", "DoS", "BruteForce"]
))

# =============================================================================
# FEATURE IMPORTANCES
# =============================================================================

print("\n--- Feature Importances (Top -> Bottom) ---")
importances = pd.Series(model.feature_importances_, index=FEATURE_COLUMNS)
print(importances.sort_values(ascending=False).to_string())
print("\nEXPECTED: avg_packet_size and unique_dst_ports near the top.")

# =============================================================================
# LIVE-FIRE SANITY CHECK
# =============================================================================

print("\n--- Live-Fire Sanity Check ---")
print(f"{'Scenario':<30} {'Expected':<12} {'Got':<12} {'Conf'}")
print("-" * 70)

labels = {0: "Normal", 1: "PortScan", 2: "DoS", 3: "BruteForce"}

test_vectors = [
    # name                          [dur,   pps,   bps,      size, ports, syn,   iat,    proto]  expected
    ("Normal HTTP",                 [8.0,   50,    50000,    1000, 2,     0.20,  0.200,  6],     "Normal"),
    ("Normal SSH session",          [30.0,  10,    4000,     400,  1,     0.10,  0.400,  6],     "Normal"),
    ("Nmap default (-sS)",          [2.0,   1500,  105000,   70,   800,   0.95,  0.001,  6],     "PortScan"),
    ("Nmap slow (--max-rate 40)",   [2.0,   40,    2800,     70,   80,    0.90,  0.025,  6],     "PortScan"),
    ("Scan Backscatter (RST)",      [2.0,   800,   48000,    60,   800,   0.01,  0.001,  6],     "Normal"),
    ("hping3 SYN flood",            [5.0,   3000,  180000,   60,   1,     1.00,  0.0003, 6],     "DoS"),
    ("hping3 UDP flood",            [5.0,   3000,  240000,   80,   1,     0.00,  0.0003, 17],    "DoS"),
    ("hping3 ICMP flood",           [5.0,   3000,  192000,   64,   1,     0.00,  0.0003, 1],     "DoS"),
    ("DoS Backscatter (RST)",       [5.0,   2000,  96000,    48,   1,     0.00,  0.0005, 6],     "Normal"),
    ("Hydra SSH -t 4",              [60.0,  20,    8000,     400,  1,     0.40,  0.500,  6],     "BruteForce"),
    ("Hydra SSH -t 64",             [30.0,  200,   80000,    400,  1,     0.45,  0.050,  6],     "BruteForce"),
]

all_pass = True
for name, vec, expected in test_vectors:
    pred   = model.predict([vec])[0]
    conf   = model.predict_proba([vec])[0].max() * 100
    got    = labels[pred]
    status = "PASS" if got == expected else "FAIL <<<<<"
    if got != expected:
        all_pass = False
    print(f"  {name:<30} {expected:<12} {got:<12} {conf:.1f}%  {status}")

print()
if all_pass:
    print("ALL SANITY CHECKS PASSED")
else:
    print("SOME CHECKS FAILED - review feature ranges before deploying.")

# =============================================================================
# SAVE
# =============================================================================

print("\n9. Saving model_flow.pkl...")
with open('model_flow.pkl', 'wb') as file:
    pickle.dump(model, file)

print("=" * 70)
print("  DONE. Next steps on ML Node:")
print("  1. sudo systemctl stop soc-ai")
print("  2. rm ~/SOC-AI/soc_alerts.db")
print("  3. sudo systemctl start soc-ai")
print("=" * 70)
