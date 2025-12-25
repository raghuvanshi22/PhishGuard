from phishguard.core.config import settings

def get_verdict(score: float) -> str:
    if score >= settings.PHISHING_THRESHOLD:
        return "PHISHING"
    elif score >= settings.SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS"
    return "LEGITIMATE"
