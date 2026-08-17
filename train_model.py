import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import pickle

print("--- SOC AI: Model Training Phase ---")
print("1. Preparing training data/features...")

# We create synthetic lab data. 
# Protocol: 6 = TCP, 1 = ICMP (Ping)
# Label: 0 = Normal Traffic, 1 = Attack (e.g., massive packet size)
data = {
    'protocol': [6, 6, 1, 1, 6, 6, 1, 6],
    'bytes': [74, 140, 74, 98, 1500, 54, 1000, 40],
    'label': [0, 0, 0, 0, 1, 0, 1, 0]
}

# Load the data into Pandas (our virtual spreadsheet)
df = pd.DataFrame(data)
X = df[['protocol', 'bytes']]  # The features the AI will study
y = df['label']                # The answers (Attack vs Normal)

print("2. Training the Random Forest model...")
# Create the AI brain with 10 "trees" in its forest
model = RandomForestClassifier(n_estimators=10, random_state=42)
model.fit(X, y)

print("3. Saving the trained model as model.pkl...")
# Export the trained brain into a file
with open('model.pkl', 'wb') as file:
    pickle.dump(model, file)

print("Success! model.pkl has been generated.")
