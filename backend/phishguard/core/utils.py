import re
from urllib.parse import urlparse

def clean_url(url: str) -> str:
    """Standardize URL format."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url

def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except Exception:
        return ""

def is_ip_address(domain: str) -> bool:
    """Check if domain is an IP address."""
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    return bool(re.match(ip_pattern, domain))
