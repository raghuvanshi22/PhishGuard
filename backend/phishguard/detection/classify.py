from phishguard.detection.rules_engine import RulesEngine
from phishguard.detection.ml_engine import MLEngine
from phishguard.detection.scorer import Scorer
from phishguard.detection.verdict import get_verdict

class PhishDetector:
    def __init__(self):
        self.rules_engine = RulesEngine()
        self.ml_engine = MLEngine()
        self.scorer = Scorer()
        
    def scan_url(self, url: str) -> dict:
        # 1. Rules Check
        rule_result = self.rules_engine.evaluate(url)
        if rule_result.get("blocked"):
            return {
                "url": url,
                "score": 1.0,
                "verdict": "PHISHING",
                "reason": "Blocked by rule",
                "details": rule_result
            }
            
        # 2. ML Inference
        ml_score = self.ml_engine.predict(url)
        
        # 3. Scoring
        # Combine Rule Score (Heuristics) and ML Score
        # If rules suggest risk (score > 0), we boost the final score.
        rule_score = rule_result.get("score", 0.0)
        
        # Logic: If rule_score is high, it pulls appropriate weight. 
        # If ML says safe (0.1) but Rules say risky (0.6) -> Final ~ 0.5 or 0.6
        # Max of both is a safe bet for a security tool.
        final_score = max(rule_score, ml_score)
        
        # Or simple weighted average if both are non-zero?
        # Let's stick to MAX strategy: if EITHER engine detects a threat, flag it.
        # This reduces False Negatives.
        
        # 4. Verdict
        verdict = get_verdict(final_score)
        
        return {
            "url": url,
            "score": round(final_score, 4),
            "verdict": verdict,
            "details": {
                "ml_score": round(ml_score, 4),
                "rule_result": rule_result
            }
        }
