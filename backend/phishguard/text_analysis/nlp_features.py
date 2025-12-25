from sklearn.feature_extraction.text import TfidfVectorizer
import pickle
import os

class NLPFeatureExtractor:
    def __init__(self, max_features=100):
        self.vectorizer = TfidfVectorizer(max_features=max_features, stop_words='english')
        self.is_fitted = False
        
    def fit(self, texts: list):
        self.vectorizer.fit(texts)
        self.is_fitted = True
        
    def transform(self, text: str):
        if not self.is_fitted:
            raise ValueError("Vectorizer not fitted")
        # Return as list for easy concatenation
        return self.vectorizer.transform([text]).toarray()[0].tolist()
    
    def save(self, path: str):
        with open(path, 'wb') as f:
            pickle.dump(self.vectorizer, f)
            
    def load(self, path: str):
         with open(path, 'rb') as f:
            self.vectorizer = pickle.load(f)
            self.is_fitted = True
