import pandas as pd
import random
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import pickle

print("--- SOC AI: V2 Model Training Phase ---")
print("1. Generating 5,000 realistic network packets...")

data = []
# Generate 4,000 NORMAL traffic packets (Small bytes, standard protocols)
for _ in range(4000):
    protocol = random.choice([6, 17]) # TCP (6) or UDP (17)
    bytes_size = random.randint(40, 400) # Normal small web traffic
    data.append([protocol, bytes_size, 0]) # 0 = Normal

# Generate 1,000 ATTACK traffic packets (Massive bytes, suspicious ICMP/TCP)
for _ in range(1000):
    protocol = random.choice([1, 6]) # ICMP Ping (1) or TCP (6)
    bytes_size = random.randint(1500, 5000) # Unusually large payloads
    data.append([protocol, bytes_size, 1]) # 1 = Attack

# Shuffle the dataset so the AI doesn't just read all normal ones first
random.shuffle(data)

print("2. Organizing data and teaching the AI...")
df = pd.DataFrame(data, columns=['protocol', 'bytes', 'label'])
X = df[['protocol', 'bytes']]
y = df['label']

# Split data: 80% for training, 20% for a final exam to test the AI
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Hire 50 Detectives instead of 10!
model = RandomForestClassifier(n_estimators=50, random_state=42)
model.fit(X_train, y_train)

print("3. Administering Final Exam to the AI...")
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)
print(f"--> AI Exam Score (Accuracy): {accuracy * 100:.2f}%")

print("4. Saving the upgraded brain to model.pkl...")
with open('model.pkl', 'wb') as file:
    pickle.dump(model, file)

print("Success! A highly intelligent model.pkl has been generated.")
