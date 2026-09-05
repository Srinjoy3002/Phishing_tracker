"""
Configuration settings, heuristic weights, high-risk lists, and MITRE ATT&CK mappings.
"""

# Risk thresholds
THRESHOLD_SAFE = 25
THRESHOLD_SUSPICIOUS = 50
THRESHOLD_MALICIOUS = 70

# Heuristic weights (Max score 100)
WEIGHTS = {
    # Lexical heuristics
    "ip_in_url": 30,
    "idn_homograph": 35,
    "brand_spoofing": 30,
    "high_entropy_domain": 15,
    "excessive_subdomains": 15,
    "suspicious_tld": 15,
    "url_redirection_trick": 30,
    "excessive_hyphens": 12,
    "url_length_excessive": 10,
    "sensitive_keywords": 15,
    "url_shortener": 10,
    "double_slash_redirect": 15,
    
    # Network & DNS heuristics
    "domain_age_under_30_days": 30,
    "domain_age_under_90_days": 15,
    "dns_no_a_record": 25,
    "dns_missing_mx_branded": 20,
    "private_ip_redirection": 25,
    
    # SSL/TLS heuristics
    "ssl_missing_or_failed": 25,
    "ssl_self_signed": 35,
    "ssl_expired": 30,
    "ssl_brand_mismatch": 30,
    "ssl_short_validity": 15,
    
    # Content & DOM heuristics (passive)
    "content_password_external_form": 40,
    "content_password_http_form": 35,
    "content_title_brand_mismatch": 30,
    "content_hidden_iframe": 15,
    "content_anti_analysis_script": 15,
}

# High-risk / frequently abused Top-Level Domains (TLDs)
SUSPICIOUS_TLDS = {
    "xyz", "top", "buzz", "work", "rest", "icu", "fit", "surf", "click", "link",
    "club", "country", "stream", "date", "racing", "kim", "science", "party",
    "download", "bid", "loan", "win", "tk", "ml", "ga", "cf", "gq", "gdn",
    "mom", "casa", "bar", "monster", "cam", "vip", "uno", "live", "lat"
}

# Known high-value targeted brands and their official base domains
TARGETED_BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "office365.com", "azure.com", "outlook.com"],
    "google": ["google.com", "accounts.google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "telegram": ["telegram.org", "t.me"],
    "twitter": ["twitter.com", "x.com"],
    "linkedin": ["linkedin.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com", "bofa.com"],
    "citi": ["citi.com", "citibank.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "metamask": ["metamask.io"],
    "dropbox": ["dropbox.com"],
    "adobe": ["adobe.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "usps": ["usps.com"]
}

# Suspicious keywords commonly weaponized in phishing campaigns
SENSITIVE_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification", "secure",
    "security", "account", "update", "banking", "ebanking", "wallet", "2fa",
    "mfa", "recovery", "support", "confirm", "credential", "auth", "authenticate",
    "billing", "invoice", "password", "reset", "unlock", "suspend", "suspended",
    "security-check", "webscr", "cmd=_login", "passcode", "otp", "validation",
    "authorize", "session", "portal", "helpdesk"
]

# URL Shorteners often used to hide the true landing destination
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "tiny.cc", "shorte.st", "cutt.ly", "rb.gy", "v.gd",
    "qr.ae", "s.id", "tiny.one", "hyperurl.co"
}

# MITRE ATT&CK mappings for technical reporting
MITRE_MAPPING = {
    "T1566.002": {
        "name": "Spearphishing Link",
        "description": "Adversary sends a link to victim leading to credential harvesting or exploit."
    },
    "T1583.001": {
        "name": "Acquire Infrastructure: Domains",
        "description": "Adversary registers lookalike or deceptive domain names."
    },
    "T1583.008": {
        "name": "Acquire Infrastructure: Malicious SSL Certificates",
        "description": "Adversary obtains SSL/TLS certificates to masquerade as legitimate services."
    },
    "T1584.004": {
        "name": "Compromise Infrastructure: Server / DNS",
        "description": "Adversary compromises DNS records or uses fast-flux dynamic DNS."
    },
    "T1056.003": {
        "name": "Input Capture: Web Portal Capture",
        "description": "Adversary mimics a web login portal to harvest credentials submitted in forms."
    },
    "T1027": {
        "name": "Obfuscated/Deceptive Code",
        "description": "Adversary obfuscates HTML elements, uses hidden iframes or disables inspection."
    }
}

# Safe User-Agent for passive scanning (simulates standard security scanner/browser)
SAFE_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 (PhishTracker-Security-Inspector/1.0)"
REQUEST_TIMEOUT = 5.0
