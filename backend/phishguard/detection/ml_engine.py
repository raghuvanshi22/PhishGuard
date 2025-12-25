import pandas as pd
from phishguard.models.model_loader import load_model
from phishguard.core.config import settings
from phishguard.extractors.url_extractor import URLExtractor

class MLEngine:
    def __init__(self):
        self.model = load_model(settings.MODEL_PATH)
        
    def predict(self, url: str) -> float:
        """
        Extract features from URL and return phishing probability.
        """
        if not self.model:
            # If model not found, return 0.5 or handle gracefully
            # For this MVP, we might train a dummy model or return 0.0
            return 0.5 
            
        # Extract features (Must match train.py logic)
        extractor = URLExtractor(url)
        features = extractor.extract_features()
        
        # Create DataFrame
        df = pd.DataFrame([features])
        
        # Predict
        try:
            # XGBoost predict_proba returns [[prob_0, prob_1]]
            probs = self.model.predict_proba(df)
            phishing_prob = probs[0][1]
            return float(phishing_prob)
        except Exception as e:
            print(f"Prediction error: {e}")
            return 0.5
