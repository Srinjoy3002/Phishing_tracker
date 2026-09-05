# 🛡️ PhishTracker: Multi-Vector Phishing Site Detector

> **Advanced Cross-Platform Phishing Analysis & Threat Intelligence Tool**  
> Tailored for **Kali Linux** penetration testers, SOC analysts, and **Windows Terminal** security workstations.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Windows%20Terminal-red.svg)]()
[![Framework](https://img.shields.io/badge/Framework-Rich%20CLI-magenta.svg)]()

---

## 📌 Overview

**PhishTracker** is an automated, multi-tiered phishing URL and website inspection tool built for cybersecurity professionals and students. Instead of relying solely on slow or reactive commercial blocklists, PhishTracker conducts **proactive multi-layer inspection** using:

1. **Lexical URL & Syntactic Heuristics** (Zero-latency offline feature extraction)
2. **Network & DNS Infrastructure Telemetry** (A/AAAA, MX, SPF, Fast-Flux detection)
3. **Domain Age & Registration Intelligence** (ICANN RDAP / WHOIS age verification)
4. **Cryptographic SSL/TLS Security Audit** (Issuer validation, self-signed detection, certificate age)
5. **Passive Safe HTML/DOM Inspection** (Non-executing analysis of credential forms, hidden iframes, anti-analysis scripts, and page title divergence)
6. **MITRE ATT&CK Framework Mapping** (Initial Access, Resource Development, Input Capture)

---

## 🎯 Key Detection Features

| Vector | Indicator & Detection Logic | MITRE ATT&CK |
| :--- | :--- | :--- |
| **Reverse Tunneling (PyPhisher)** | Detects ephemeral reverse-tunnels (`trycloudflare.com`, `loca.lt`, `ngrok-free.app`, `serveo.net`) weaponized by automated phishing kits (PyPhisher, Zphisher). | `T1585` |
| **Automated Subdomain Pattern** | Identifies Cloudflare Quick Tunnel 4-word auto-generated subdomains (e.g. `word1-word2-word3-word4.trycloudflare.com`). | `T1583.001` |
| **Weaponized Masking Bait** | Evaluates the deceptive user-info bait string preceding `@` (e.g., `get-unlimited-followers-for-instagram@...`). | `T1566.002` |
| **Phishing Kit Endpoints** | Fingerprints standard capture scripts (`login.php`, `post.php`, `process.php`, `capture.php`) used by cloned templates. | `T1056.003` |
| **Victim IP Logger Traps** | Detects client-side victim tracking scripts (`ip-api.com`, `api.ipify.org`, `ipinfo.io`) that record visitor IP and geolocation. | `T1027` |
| **Exfiltration Webhooks** | Identifies Telegram Bot API tokens (`api.telegram.org/bot`) and Discord webhooks embedded in page scripts. | `T1056.003` |
| **Punycode / Homograph** | Detects IDN Homograph attacks (`xn--`) where Cyrillic or Greek lookalike characters spoof Latin characters (e.g., `pаypal.com`). | `T1583.001` |
| **IP-in-Hostname** | Flags raw IPv4, IPv6, Hexadecimal (`0x...`), and Dword encoded IP addresses used in place of domain names. | `T1566.002` |
| **Brand Combosquatting** | Cross-references high-profile brands (Instagram, Facebook, Google, Apple, Amazon, Banking) combined with lure keywords. | `T1566.002` |
| **Shannon Entropy** | Calculates mathematical uncertainty $H(X)$ to detect Domain Generation Algorithms (DGA) and randomized malware URLs. | `T1584.004` |
| **Suspicious TLDs** | Flags domains registered under high-abuse top-level domains (`.xyz`, `.top`, `.buzz`, `.tk`, `.work`, `.rest`). | `T1583.001` |
| **SSL/TLS Vulnerabilities** | Detects self-signed certificates, expired certs, automated free certificates on banking portals, and freshly provisioned certs. | `T1583.008` |
| **Credential Form Hijack** | Analyzes HTML DOM to detect `<input type="password">` forms submitting credentials to foreign third-party hosts or cleartext HTTP. | `T1056.003` |
| **Title Divergence** | Flags web pages claiming to be a brand in `<title>` while hosted on an unverified domain. | `T1566.002` |
| **Anti-Analysis Scripts** | Uncovers JavaScript blocking right-clicks (`oncontextmenu`), Developer Tools (F12), or keyboard shortcuts. | `T1027` |


---

## 🚀 Installation & Setup

### 🪟 Windows Terminal / PowerShell / Command Prompt

```powershell
# 1. Clone or navigate to the project directory
cd D:\projects\Phishing_tracker

# 2. Install required Python packages
python -m pip install -r requirements.txt

# 3. Verify installation
python phish_tracker.py --help
```

### 🐉 Kali Linux (Bash / Zsh)

```bash
# 1. Clone repository
git clone https://github.com/Srinjoy3002/Phishing_tracker.git
cd Phishing_tracker

# 2. Install system packages & python dependencies
sudo apt update
sudo apt install -y python3 python3-pip python3-venv

# (Optional: Use a virtual environment)
python3 -m venv venv
source venv/bin/activate

# 3. Install requirements
pip3 install -r requirements.txt

# 4. Make executable and run
chmod +x phish_tracker.py
./phish_tracker.py --help
```

---

## 💻 Usage & CLI Modes

### 1. Interactive REPL Mode (Recommended for Daily Triage)
Launch the tool without arguments to enter an interactive cybersecurity shell:
```bash
python phish_tracker.py
```

### 2. Single Target Inspection
Analyze a specific URL or domain:
```bash
python phish_tracker.py -u "http://paypal-security-verification-account.xyz/webscr?cmd=_login"
```

### 3. Batch Target Triage from File
Scan multiple URLs simultaneously and produce a threat matrix table:
```bash
python phish_tracker.py -f samples/test_urls.txt
```

### 4. Fast Mode (Offline / Lexical Only)
Skip network resolution, WHOIS, and SSL queries to perform instantaneous offline regex & Shannon entropy checks:
```bash
python phish_tracker.py -u "https://suspicious-domain.top/login" --fast
```

### 5. Stealth & OPSEC Protection Modes (Hide IP from PyPhisher)
When analyzing live phishing kits (e.g., PyPhisher, Zphisher), the server executes IP loggers (`ip-api.com`). Shield your identity using:

```bash
# Route all traffic through Tor (anonymizes your IP & geolocation)
python phish_tracker.py -u "https://occupation-exposure-piece-spam.trycloudflare.com" --tor

# Route via custom SOCKS5 or HTTP proxy
python phish_tracker.py -u "https://suspicious-site.com" --proxy "socks5h://127.0.0.1:9050"

# Zero-Touch Passive Recon (Zero packets sent to target web server, 100% invisible to PyPhisher)
python phish_tracker.py -u "https://suspicious-site.com" --passive
```

### 6. Exporting Incident Reports (JSON & Markdown)
Generate compliance, SIEM-ready JSON, and incident response Markdown reports:
```bash
python phish_tracker.py -u "http://192.168.1.100/secure-banking/login.php" --json report.json --markdown report.md
```

### 7. One-Click Self-Updating
Keep rules, signatures, and dependencies up to date with a single command:
```bash
python phish_tracker.py --update
```



---

## 📊 Threat Classification System

PhishTracker computes an aggregate risk score ($0 - 100$):

$$\text{Risk Score} = \min\left(100, \sum_{i} W_i \cdot \mathbb{I}(\text{Indicator}_i)\right)$$

* 🟢 **0 – 24 (BENIGN / SAFE)**: Verified domain, valid infrastructure, normal lexical characteristics.
* 🟡 **25 – 49 (LOW RISK)**: Minor anomalies (e.g. shortener, young age); standard monitoring recommended.
* 🟠 **50 – 69 (SUSPICIOUS)**: Multiple risk indicators present; manual triage recommended before access.
* 🔴 **70 – 100 (CRITICAL PHISHING)**: High-confidence active credential harvesting, brand impersonation, or deceptive attack infrastructure.

---

## 📂 Project Architecture

```
D:\projects\Phishing_tracker\
│
├── phish_tracker.py          # CLI application entrypoint & interactive REPL
├── requirements.txt          # Python dependencies (rich, requests, dnspython, cryptography)
├── README.md                 # Project documentation & Kali/Windows setup guide
│
├── core/                     # Modular detection engines
│   ├── __init__.py           # Package initializer
│   ├── banner.py             # Cyberpunk ASCII terminal banner & cross-platform styles
│   ├── config.py             # Heuristic weights, brand targets, TLDs, and MITRE mapping
│   ├── lexical.py            # URL lexical analysis, Punycode, and Shannon Entropy
│   ├── dns_intel.py          # DNS resolution, MX records, and Fast-Flux detection
│   ├── whois_intel.py        # ICANN RDAP & WHOIS domain age retrieval
│   ├── ssl_checker.py        # TLS certificate audit, self-signed & issuer verification
│   ├── content_checker.py    # Safe passive HTML/DOM inspection (credential forms & iframes)
│   ├── engine.py             # Risk scoring engine & SOC recommendation generator
│   └── reporter.py           # Rich terminal dashboard renderer, JSON & Markdown exporters
│
└── samples/
    └── test_urls.txt         # Pre-configured test corpus (benign & malicious test cases)
```

---

## 🎓 Academic Defense & Presentation Guide

If presenting this project for your cybersecurity degree or viva:

1. **Demonstrate Both Environments**: Run the tool in Windows Terminal, show the ASCII banner, colored risk gauge, and telemetry table. Explain that Python's socket and RDAP stack makes it 100% portable to Kali Linux.
2. **Explain the Blind Spots of Blocklists**: Emphasize that traditional blocklists (PhishTank, Google Safe Browsing) only catch phishing sites *after* victims have already been compromised. PhishTracker catches **zero-day phishing** via lexical patterns, newly registered domain signals, and DOM credential analysis.
3. **Walk Through the Heuristics**:
   - Show how the **Shannon Entropy** calculation catches DGA domains.
   - Show how the **Punycode decoder** reveals IDN homograph spoofing (`xn--...`).
   - Show how the **DOM form analyzer** catches credentials being posted to external IP addresses.
4. **Highlight Operational Security (OPSEC)**: Explain why passive HTTP fetching without executing JavaScript is critical for defensive triage to prevent client-side drive-by exploit payload execution.

---

## 🛠️ Contributing & Adding New Features

Want to expand the brand database, add newly discovered reverse-tunnel services, or improve detection signatures?

- **[Read the Full Contributor & Developer Guide](CONTRIBUTING.md)**
- **Adding a Brand in 1 Step:** Add domain to `TARGETED_BRANDS` in [`core/config.py`](core/config.py).
- **Adding a Tunnel Provider:** Add domain to `REVERSE_TUNNEL_SERVICES` in [`core/config.py`](core/config.py).
- **Running Tests:** `python -m unittest examples/test_pyphisher_detection.py`
- **Publishing Updates:** `git add . && git commit -m "feat: ..." && git push origin main`

---

## 📜 License
Developed for academic, research, and defensive security operations.  
Released under the MIT License.

