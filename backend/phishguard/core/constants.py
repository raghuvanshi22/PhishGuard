PROTECTED_BRANDS = {
    "paypal": ["paypal.com", "paypal.me"],
    "google": ["google.com", "accounts.google.com", "drive.google.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "azure.com"],
    "amazon": ["amazon.com", "aws.amazon.com"],
    "facebook": ["facebook.com", "fb.com", "messenger.com"],
    "apple": ["apple.com", "icloud.com"],
    "netflix": ["netflix.com"],
    "instagram": ["instagram.com"],
    "linkedin": ["linkedin.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "dropbox": ["dropbox.com"],
    "adobe": ["adobe.com"],
    "twitter": ["twitter.com", "x.com"],
    "whatsapp": ["whatsapp.com"],
    "telegram": ["telegram.org"],
    "zoom": ["zoom.us"],
    "tiktok": ["tiktok.com"],
    "roblox": ["roblox.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "coinbase": ["coinbase.com"],
    "blockchain": ["blockchain.com"],
    "binance": ["binance.com"],
}

SAFE_DOMAINS = set()
for domains in PROTECTED_BRANDS.values():
    SAFE_DOMAINS.update(domains)

SUSPICIOUS_KEYWORDS = [
    "verify", "urgent", "account", "suspended", "login", "password", 
    "credential", "update", "confirm", "security", "alert",
    "security-alert", "verify-account", "update-payment", "login-attempt", 
    "unusual-activity", "locked", "confirm-identity", "secure-login",
    "account-recovery", "password-reset", "billing-issue"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".gq", ".tk", ".ml", ".cf", ".ga", ".bd", ".ke", ".pk", ".cn",
    ".ru", ".rest", ".fit"
]

SHORTENING_SERVICES = [
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "is.gd", "cli.gs",
    "yfrog.com", "migre.me", "ff.im", "tiny.cc", "url4.eu", "twit.ac",
    "su.pr", "twurl.nl", "snipurl.com", "snipurl.com", "cl.lz"
]
