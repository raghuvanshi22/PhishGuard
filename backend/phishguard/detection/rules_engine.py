from phishguard.core.constants import PROTECTED_BRANDS, SUSPICIOUS_KEYWORDS, SUSPICIOUS_TLDS, SAFE_DOMAINS
import tldextract
import re

class RulesEngine:
    def evaluate(self, url: str) -> dict:
        """
        Returns a dict with:
        - blocked: bool (if explicitly malicious)
        - score: float (0.0 to 1.0, where 1.0 is definitely phishing)
        - rules_triggered: list of descriptions
        """
        rules_triggered = []
        score = 0.0
        blocked = False
        
        # Parse URL
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        subdomain = extracted.subdomain
        
        # 0. Allowlist Check (Fast Pass)
        if domain in SAFE_DOMAINS:
            return {"blocked": False, "score": 0.0, "rules_triggered": ["Safe Domain"]}

        # 1. Brand Impersonation Check (Critical)
        # If URL contains "paypal" but is NOT paypal.com -> BLOCK
        url_lower = url.lower()
        for brand, valid_domains in PROTECTED_BRANDS.items():
            if brand in url_lower:
                # Check if it matches any valid domain for this brand
                is_valid = False
                for valid_d in valid_domains:
                    if valid_d in url_lower:
                        # Check precise match to avoid "paypal-scam.com" passing as "paypal.com"
                        # Simple check: is the base domain correct?
                        if domain == valid_d or domain.endswith("." + valid_d): # Simplification
                             is_valid = True
                             break
                
                if not is_valid:
                    blocked = True
                    score = 1.0
                    rules_triggered.append(f"Brand Impersonation Detected: {brand}")
                    return {"blocked": True, "score": 1.0, "rules_triggered": rules_triggered}

        # 2. Suspicious Keywords in Domain/Subdomain
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in domain or kw in subdomain:
                score += 0.3
                rules_triggered.append(f"Suspicious Keyword: {kw}")

        # 3. Suspicious TLDs
        if f".{extracted.suffix}" in SUSPICIOUS_TLDS:
            score += 0.2
            rules_triggered.append(f"Suspicious TLD: .{extracted.suffix}")

        # 4. IP Address Usage
        # Regex for IP
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            score += 0.4
            rules_triggered.append("IP Address Detected")

        # Cap score
        score = min(score, 0.9) # Heuristics alone shouldn't be 1.0 unless brand blocking

        if score > 0.7:
             rules_triggered.append("High Heuristic Score")

        return {
            "blocked": blocked, 
            "score": score, 
            "rules_triggered": rules_triggered
        }
