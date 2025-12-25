import tldextract
import math
import re
from phishguard.core.utils import clean_url, is_ip_address
from phishguard.core.constants import SUSPICIOUS_TLDS, SHORTENING_SERVICES, SUSPICIOUS_KEYWORDS

class URLExtractor:
    def __init__(self, url: str):
        self.url = clean_url(url)
        self.parsed = tldextract.extract(self.url)
        self.domain = self.parsed.domain + "." + self.parsed.suffix
        if self.parsed.subdomain:
            self.full_domain = self.parsed.subdomain + "." + self.domain
        else:
            self.full_domain = self.domain

    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy for a given string."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy

    def extract_features(self) -> dict:
        features = {}
        
        # Length features
        features['url_length'] = len(self.url)
        features['domain_length'] = len(self.domain)
        features['hostname_length'] = len(self.full_domain)
        
        # Character counts
        features['count_dots'] = self.url.count('.')
        features['count_hyphens'] = self.url.count('-')
        features['count_at'] = self.url.count('@')
        features['count_percent'] = self.url.count('%')
        features['count_digits'] = sum(c.isdigit() for c in self.url)
        
        # Entropy
        features['url_entropy'] = self.calculate_entropy(self.url)
        features['domain_entropy'] = self.calculate_entropy(self.domain)
        
        # Boolean features
        features['is_ip'] = int(is_ip_address(self.parsed.domain))
        features['is_suspicious_tld'] = int(self.parsed.suffix in SUSPICIOUS_TLDS)
        features['has_https'] = int(self.url.startswith("https"))
        features['is_shortened'] = int(self.domain in SHORTENING_SERVICES)
        
        # Keyword analysis
        url_lower = self.url.lower()
        features['has_suspicious_keyword'] = int(any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS))
        
        return features
