class IntentDetector:
    def detect_urgency(self, text: str) -> bool:
        # Simple heuristic for now
        urgent_words = ["immediately", "24 hours", "suspended"]
        return any(w in text.lower() for w in urgent_words)
