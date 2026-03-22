import pandas as pd
import base64
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

print("Loading and decoding training data...")

# Decode the base64 encoded payloads
df = pd.read_csv('training_data_encoded.csv', encoding='utf-8')
df['payload'] = df['payload_encoded'].apply(
    lambda x: base64.b64decode(str(x).encode('utf-8')).decode('utf-8', errors='replace')
)
df = df[['payload', 'Label']].dropna()
df['Label'] = pd.to_numeric(df['Label'], errors='coerce')
df = df.dropna()
df['Label'] = df['Label'].astype(int)

print(f"Dataset loaded: Safe={len(df[df['Label']==0])}, Attack={len(df[df['Label']==1])}")

# Vectorize
print("Training Sentinel AI Brain... please wait.")
vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(1,4), max_features=80000)
X = vectorizer.fit_transform(df['payload'].values.astype('U'))
y = df['Label']

# Train
model = RandomForestClassifier(n_estimators=300, random_state=42, class_weight='balanced')
model.fit(X, y)

# Save
joblib.dump(model, 'sentinel_model.pkl')
joblib.dump(vectorizer, 'vectorizer.pkl')

print("Success! sentinel_model.pkl and vectorizer.pkl created.")
