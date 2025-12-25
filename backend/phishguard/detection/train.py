import pandas as pd
import numpy as np
import pickle
import os
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from xgboost import XGBClassifier
from phishguard.extractors.url_extractor import URLExtractor
from phishguard.core.config import settings
import time

# Configuration
DATASET_PATH = "datasets/raw/phishing_10k.csv"
MODEL_PATH = settings.MODEL_PATH

def load_and_preprocess_data(path):
    print(f"Loading dataset from {path}...")
    try:
        df = pd.read_csv(path)
    except FileNotFoundError:
        print(f"Error: Dataset not found at {path}")
        return None, None

    print(f"Dataset loaded: {len(df)} rows.")
    
    # Normalize column names
    df.columns = [c.lower() for c in df.columns]
    
    # Identify URL and Label columns
    # Shreyagopal dataset often uses 'Domain' and 'Label'
    url_col = 'domain' if 'domain' in df.columns else 'url'
    target_col = 'label'

    if url_col not in df.columns or target_col not in df.columns:
        print(f"Error: Missing columns. Found: {list(df.columns)[:5]}...")
        return None, None

    # Drop duplicates
    original_len = len(df)
    df.drop_duplicates(subset=url_col, inplace=True)
    print(f"Dropped {original_len - len(df)} duplicates.")

    # Encode Labels
    # Check values
    unique_labels = df[target_col].unique()
    print(f"Unique labels: {unique_labels}")
    
    # Map valid labels
    # Usually 0/1 in this dataset, but let's be safe
    # If already 0/1, map won't hurt if we handle it
    # If strings '0'/'1' or 'legitimate'
    
    def map_label(val):
        s = str(val).lower()
        if s in ['1', 'phishing', 'bad']: return 1
        if s in ['0', 'legitimate', 'good']: return 0
        return None

    df['target'] = df[target_col].apply(map_label)
    
    # Drop rows with unknown labels
    unknowns = df[df['target'].isna()]
    if not unknowns.empty:
        print(f"Warning: {len(unknowns)} rows with unknown labels dropped.")
        df.dropna(subset=['target'], inplace=True)
    
    return df[url_col], df['target']

def extract_features_batch(urls):
    print(f"Extracting features for {len(urls)} URLs. This may take a while...")
    start_time = time.time()
    
    features_list = []
    total = len(urls)
    
    for i, url in enumerate(urls):
        if i % 5000 == 0 and i > 0:
            print(f"Processed {i}/{total} URLs...")
        
        try:
            extractor = URLExtractor(url)
            features_list.append(extractor.extract_features())
        except Exception as e:
            # Fallback for errors
            print(f"Error extracting {url}: {e}")
            features_list.append({}) # Empty dict or valid default

    duration = time.time() - start_time
    print(f"Feature extraction completed in {duration:.2f} seconds.")
    
    return pd.DataFrame(features_list)

def train_model():
    print("Starting Training Pipeline...")
    
    # 1. Load Data
    urls, y = load_and_preprocess_data(DATASET_PATH)
    if urls is None:
        return

    # 2. Extract Features
    # For MVP, maybe sample if too large to avoid timeout during demo
    # But user asked for accuracy, so let's try full or large subset
    MAX_SAMPLES = 20000 # Limit to 20k for reasonable speed in this environment
    if len(urls) > MAX_SAMPLES:
        print(f"Dataset too large. Sampling {MAX_SAMPLES} for training efficiency...")
        # Ensure balanced sampling if possible, but random is okay for now
        # Combine to sample
        temp_df = pd.DataFrame({'url': urls, 'target': y})
        sampled_df = temp_df.sample(n=MAX_SAMPLES, random_state=42)
        urls = sampled_df['url']
        y = sampled_df['target']
    
    X = extract_features_batch(urls)
    
    # Fill NA if any
    X.fillna(0, inplace=True)

    # 3. Split Data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # 4. Train XGBoost
    print("Training XGBoost Classifier...")
    model = XGBClassifier(
        n_estimators=100,
        learning_rate=0.1,
        max_depth=5,
        use_label_encoder=False,
        eval_metric='logloss'
    )
    model.fit(X_train, y_train)
    
    # 5. Evaluate
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\nModel Accuracy: {acc * 100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # 6. Save Model
    print(f"Saving model to {MODEL_PATH}...")
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    
    print("Training Complete.")

if __name__ == "__main__":
    train_model()
