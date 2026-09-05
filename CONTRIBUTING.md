# 🛠️ PhishTracker Developer & Contributor Guide

Thank you for your interest in improving and expanding **PhishTracker**! Whether you are adding newly discovered phishing kits, expanding the brand database, or improving OPSEC controls, this guide outlines the architecture and workflow.

---

## 📂 Architecture Overview

All detection modules reside inside the [`core/`](core/) package:

| File | Purpose | When to Modify |
| :--- | :--- | :--- |
| [`core/config.py`](core/config.py) | Signatures, thresholds, targeted brands, tunnel providers, kit endpoints, and regexes. | Adding new brands, tunnel services, or phishing kit signatures. |
| [`core/lexical.py`](core/lexical.py) | Offline URL analysis, Punycode, Shannon Entropy, and URL masking tricks (`@`). | Adding new syntactic URL heuristics. |
| [`core/dns_intel.py`](core/dns_intel.py) | Live DNS resolution (A/AAAA, MX, SPF, TTL) & Fast-Flux detection. | Adding new DNS or network infrastructure checks. |
| [`core/whois_intel.py`](core/whois_intel.py) | ICANN RDAP & socket WHOIS domain age retrieval. | Modifying domain age or registrar heuristics. |
| [`core/ssl_checker.py`](core/ssl_checker.py) | Cryptographic TLS audit (issuer, self-signed, cert age). | Adding certificate trust checks. |
| [`core/content_checker.py`](core/content_checker.py) | Passive HTML/DOM inspector (forms, kit endpoints, victim IP loggers). | Adding detection for new phishing templates. |
| [`core/engine.py`](core/engine.py) | Risk scoring matrix, compound rules, and OPSEC controller. | Adjusting score weights or adding compound rules. |
| [`core/reporter.py`](core/reporter.py) | Rich terminal UI, gauges, tables, JSON/Markdown exporters. | Changing terminal dashboard layout or export formats. |

---

## 🚀 How to Add New Features

### 1. Adding a New Targeted Brand
Phishers frequently clone high-profile services (e.g. Spotify, Discord, Uber, Zoom). To add protection for a new brand:

1. Open [`core/config.py`](core/config.py).
2. Locate `TARGETED_BRANDS` and add the brand name and its legitimate domains:
   ```python
   TARGETED_BRANDS = {
       # Existing brands...
       "spotify": ["spotify.com"],
       "zoom": ["zoom.us", "zoom.com"],
       "uber": ["uber.com"],
   }
   ```
3. *Effect:* If any unauthorized domain or tunnel references `spotify` or displays `Spotify` in its `<title>`, PhishTracker will automatically flag it with `[T1566.002] Brand Spoofing`.

---

### 2. Adding Newly Discovered Reverse-Tunnel Services
Phishing frameworks (like PyPhisher, Zphisher, Maskphish) frequently switch to new free tunneling providers.

1. Open [`core/config.py`](core/config.py).
2. Locate `REVERSE_TUNNEL_SERVICES` and add the new tunnel domain:
   ```python
   REVERSE_TUNNEL_SERVICES = {
       "trycloudflare.com",
       "ngrok-free.app",
       "loca.lt",
       "new-tunnel-provider.dev",  # <-- Add here
   }
   ```
3. *Effect:* Any URL hosted on this service will immediately be flagged under `[T1585] Ephemeral Reverse Tunnel Host`.

---

### 3. Adding New Phishing Kit Endpoints & Endpoints
If a new kit posts credentials to a custom script:

1. Open [`core/config.py`](core/config.py).
2. Add the endpoint name to `PHISHING_KIT_ENDPOINTS`:
   ```python
   PHISHING_KIT_ENDPOINTS = {
       "login.php", "post.php", "capture.php",
       "stealer.php",  # <-- Add here
   }
   ```

---

### 4. Adding Victim IP-Logger / Exfiltration Patterns
If an attacker uses a new IP-logging API or webhook:

1. Open [`core/config.py`](core/config.py).
2. Add the regex pattern to `EXFILTRATION_PATTERNS`:
   ```python
   EXFILTRATION_PATTERNS = {
       "new_logger": (r"api\.new-ip-logger\.com", "Custom Victim IP Logger Signature"),
   }
   ```

---

## 🧪 Testing Your Changes

Before publishing, always verify that your modifications pass existing test suites:

```bash
# Run the PyPhisher and Cloudflare tunnel test suite:
python -m unittest examples/test_pyphisher_detection.py

# Test against the sample corpus:
python phish_tracker.py -f samples/test_urls.txt --fast
```

To add a new unit test for your feature, create a test case inside [`examples/test_pyphisher_detection.py`](examples/test_pyphisher_detection.py).

---

## 📦 How to Version & Publish Updates to GitHub

When your changes are tested and ready to ship:

### Step 1: Bump the Version
In [`core/__init__.py`](core/__init__.py):
```python
__version__ = "1.1.0"  # Increment version
```

### Step 2: Commit and Push
```powershell
# 1. Stage modified files
git add .

# 2. Commit with a clear descriptive message
git commit -m "feat: added Zoom & Spotify brand signatures, added new-tunnel.dev detection"

# 3. Push live to GitHub
git push origin main
```

---

## 🔄 How Users Update Their Installation

Users of PhishTracker can pull your latest updates instantly:

### Method 1: The Built-in 1-Click Updater
```bash
python phish_tracker.py --update
```

### Method 2: Standard Git Pull
```bash
git pull origin main
pip install -r requirements.txt --upgrade
```
