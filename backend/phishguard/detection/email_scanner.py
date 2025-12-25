import re
import email
from email.policy import default
from phishguard.detection.classify import PhishDetector

class EmailScanner:
    def __init__(self):
        self.url_detector = PhishDetector()
        # Keywords indicating urgency or pressure
        self.suspicious_keywords = [
            "urgently", "immediate action", "verify your account",
            "password expiration", "unauthorized access", "suspended",
            "cancell", "bitcoin", "fund transfer"
        ]

    def scan_email(self, raw_content: str) -> dict:
        """
        Parses and analyzes a raw email for phishing indicators.
        """
        results = {
            "verdict": "SAFE",
            "score": 0.0,
            "spoofing_detected": False,
            "suspicious_urls": [],
            "keywords_found": [],
            "details": {}
        }

        try:
            # 1. Parse Email
            msg = email.message_from_string(raw_content, policy=default)
            
            # 2. Extract Headers
            headers = {
                "From": msg.get("From", ""),
                "Return-Path": msg.get("Return-Path", ""),
                "Subject": msg.get("Subject", "")
            }
            results["details"]["headers"] = headers

            # 3. Check Spoofing (Basic Mismatch)
            # Simple heuristic: If extracted emails from 'From' and 'Return-Path' differ significantly
            from_email = self._extract_email(headers["From"])
            return_path = self._extract_email(headers["Return-Path"])
            
            if from_email and return_path and from_email != return_path:
                results["spoofing_detected"] = True
                results["details"]["spoofing_reason"] = f"Mismatch: From({from_email}) != Return-Path({return_path})"

            # 4. Extract Body & Scan for Keywords
            body = self._get_email_body(msg)
            results["details"]["body_preview"] = body[:200] + "..." if len(body) > 200 else body
            
            found_keywords = [kw for kw in self.suspicious_keywords if kw.lower() in body.lower()]
            results["keywords_found"] = found_keywords

            # 5. Extract & Scan URLs
            urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body)
            
            max_url_score = 0.0
            for url in urls:
                scan_res = self.url_detector.scan_url(url)
                if scan_res["verdict"] in ["PHISHING", "SUSPICIOUS"]:
                    results["suspicious_urls"].append({
                        "url": url,
                        "verdict": scan_res["verdict"],
                        "score": scan_res["score"]
                    })
                    max_url_score = max(max_url_score, scan_res["score"])

            # 6. Final Verdict Logic
            score = 0.0
            
            # Weighted Scoring
            if results["spoofing_detected"]: score += 0.4
            if len(found_keywords) > 0: score += 0.2 + (len(found_keywords) * 0.05)
            score += max_url_score * 0.6  # URLs are strong indicators
            
            results["score"] = min(score, 1.0) # Cap at 1.0

            if results["score"] > 0.75:
                results["verdict"] = "PHISHING"
            elif results["score"] > 0.4:
                results["verdict"] = "SUSPICIOUS"
            
        except Exception as e:
            results["error"] = str(e)
            
        return results

    def _extract_email(self, text):
        match = re.search(r'[\w.+-]+@[\w-]+\.[\w.-]+', text)
        return match.group(0) if match else None

    def _get_email_body(self, msg):
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                cdispo = str(part.get('Content-Disposition'))
                
                # skip attachments
                if 'attachment' in cdispo:
                    continue
                    
                if ctype == 'text/plain':
                    return part.get_payload(decode=True).decode()
                elif ctype == 'text/html':
                    # Basic HTML stripping could go here, returning raw for now
                    return part.get_payload(decode=True).decode()
        else:
            return msg.get_payload(decode=True).decode()
        return ""
