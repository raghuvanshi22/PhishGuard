import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "PhishGuard"
    VERSION: str = "0.1.0"
    DEBUG: bool = False
    
    # Model Paths
    MODEL_PATH: str = "models/phishing_model.pkl"
    
    # Thresholds
    PHISHING_THRESHOLD: float = 0.8
    SUSPICIOUS_THRESHOLD: float = 0.5
    
    # Database
    MONGO_URI: str = "mongodb://localhost:27017"
    MONGO_DB_NAME: str = "phishguard"
    
    # Security
    API_KEY: str = os.getenv("PHISHGUARD_API_KEY", "phishguard-secret-key")
    API_KEY_NAME: str = "X-API-Key"
    
    class Config:
        env_file = ".env"

settings = Settings()
