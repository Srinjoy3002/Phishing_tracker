"""
Configuration settings, heuristic weights, high-risk lists, and MITRE ATT&CK mappings.
Includes signatures for Reverse Tunneling services, PyPhisher/Zphisher kits, and OPSEC rules.
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
    "url_masked_bait": 35,
    "excessive_hyphens": 12,
    "url_length_excessive": 10,
    "sensitive_keywords": 15,
    "url_shortener": 10,
    "double_slash_redirect": 15,
    
    # Reverse Tunnel & Ephemeral Hosting (PyPhisher / Zphisher / Ngrok / Cloudflare Tunnels)
    "reverse_tunnel_service": 40,
    "tunnel_random_subdomains": 20,
    "reverse_tunnel_with_login": 55,
    
    # Network & DNS heuristics
    "domain_age_under_30_days": 30,
    "domain_age_under_90_days": 15,
    "dns_no_a_record": 25,
    "dns_missing_mx_branded": 20,
    "private_ip_redirection": 25,
    "fast_flux_dns": 25,
    
    # SSL/TLS heuristics
    "ssl_missing_or_failed": 25,
    "ssl_self_signed": 35,
    "ssl_expired": 30,
    "ssl_brand_mismatch": 30,
    "ssl_short_validity": 15,
    
    # Content & DOM heuristics (passive)
    "content_password_external_form": 40,
    "content_password_http_form": 35,
    "content_title_brand_mismatch": 35,
    "content_hidden_iframe": 15,
    "content_anti_analysis_script": 15,
    
    # Phishing Kit & Tracker Artifacts (PyPhisher / Zphisher footprints)
    "phishing_kit_endpoint": 35,
    "credential_exfiltration_channel": 45,
    "victim_tracking_script": 30,
    "geolocation_harvesting": 35,
    "webcam_harvesting_script": 40
}

# Reverse Tunnel & Port-Forwarding Services heavily weaponized in automated phishing kits
REVERSE_TUNNEL_SERVICES = {
    "trycloudflare.com", "cloudflarepreview.com",
    "loca.lt", "ngrok-free.app", "ngrok.io", "ngrok.app",
    "serveo.net", "pinggy.link", "pinggy.io",
    "localxpose.io", "loclx.io", "portmap.io", "portmap.host",
    "pagekite.me", "telebit.io", "telebit.cloud",
    "tunnelto.dev", "localhost.run", "lhr.life", "beameio.net",
    "burpcollaborator.net", "oastify.com", "interactsh.com", "playit.gg"
}

# Typical credential capture endpoints used in PyPhisher, Zphisher, Maskphish, and HiddenEye
PHISHING_KIT_ENDPOINTS = {
    "login.php", "post.php", "pass.php", "process.php", "capture.php",
    "action.php", "submit.php", "log.php", "ip.php", "verify.php",
    "auth.php", "session.php", "checkpoint.php", "save.php",
    "next.php", "c.php", "secure.php", "accounts/login.php", "login_auth.php"
}

# Signatures for exfiltration webhooks, IP loggers, and device sensors in HTML/JS
EXFILTRATION_PATTERNS = {
    "telegram_bot": (r"api\.telegram\.org/bot[0-9]+:[a-zA-Z0-9_\-]+", "Telegram Bot API Credential Exfiltration Webhook"),
    "discord_webhook": (r"discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_\-]+", "Discord Webhook Credential Exfiltration"),
    "ip_logger_api": (r"(?:ip-api\.com/json|api\.ipify\.org|ipinfo\.io|extreme-ip-lookup\.com|freegeoip\.app|geoplugin\.net)", "Victim IP/Geolocation Logger API (PyPhisher Footprint)"),
    "geolocation_api": (r"navigator\.geolocation\.getCurrentPosition", "HTML5 Browser Geolocation Harvester"),
    "camphish_webrtc": (r"navigator\.mediaDevices\.getUserMedia", "Webcam/Microphone Permission Harvester (CamPhish)")
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
    "instagram": ["instagram.com"],
    "facebook": ["facebook.com", "fb.com"],
    "whatsapp": ["whatsapp.com"],
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "office365.com", "azure.com", "outlook.com"],
    "google": ["google.com", "accounts.google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de"],
    "netflix": ["netflix.com"],
    "telegram": ["telegram.org", "t.me"],
    "twitter": ["twitter.com", "x.com"],
    "linkedin": ["linkedin.com"],
    "snapchat": ["snapchat.com"],
    "tiktok": ["tiktok.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "discord": ["discord.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com", "bofa.com"],
    "citi": ["citi.com", "citibank.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "metamask": ["metamask.io"],
    "dropbox": ["dropbox.com"],
    "adobe": ["adobe.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"]
}

# Suspicious keywords commonly weaponized in phishing campaigns
SENSITIVE_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification", "secure",
    "security", "account", "update", "banking", "ebanking", "wallet", "2fa",
    "mfa", "recovery", "support", "confirm", "credential", "auth", "authenticate",
    "billing", "invoice", "password", "reset", "unlock", "suspend", "suspended",
    "security-check", "webscr", "cmd=_login", "passcode", "otp", "validation",
    "authorize", "session", "portal", "helpdesk", "followers", "free-followers",
    "unlimited-followers", "free-likes", "get-followers", "air-drop", "giveaway"
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
        "description": "Adversary registers lookalike, reverse-tunnel, or deceptive domain names."
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
    },
    "T1585": {
        "name": "Establish Accounts: Ephemeral Reverse Proxy / Webhook",
        "description": "Adversary leverages ephemeral tunnels (Cloudflare, Ngrok) or webhooks to route illicit traffic."
    }
}

# Realistic Browser Headers (Mimics standard Google Chrome 122 on Windows to avoid fingerprinting)
STEALTH_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-Ch-Ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
    "DNT": "1"
}

REQUEST_TIMEOUT = 6.0

# Default Tor SOCKS5 proxy endpoints
TOR_PROXIES = {
    "standard": "socks5h://127.0.0.1:9050",
    "browser": "socks5h://127.0.0.1:9150"
}
