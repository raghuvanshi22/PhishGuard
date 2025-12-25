class Scorer:
    def calculate_score(self, rule_score: float, ml_score: float) -> float:
        # Weighted average or priority logic
        if rule_score > 0.9:
            return rule_score
        return ml_score # Simplistic fallback
