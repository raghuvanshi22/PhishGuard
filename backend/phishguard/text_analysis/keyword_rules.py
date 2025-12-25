from phishguard.core.constants import SUSPICIOUS_KEYWORDS

def check_keywords(text: str) -> dict:
    text_lower = text.lower()
    matches = [kw for kw in SUSPICIOUS_KEYWORDS if kw in text_lower]
    return {
        'keyword_matches': len(matches),
        'matched_keywords': matches
    }
