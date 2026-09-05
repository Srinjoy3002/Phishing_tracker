"""
Domain Registration and WHOIS / RDAP Intelligence Analyzer.
Extracts domain age, registrar telemetry, and detects freshly registered domains.
"""

from datetime import datetime, timezone
import json
import re
import socket
import urllib.request
from typing import Optional


def parse_date_string(date_str: str) -> Optional[datetime]:
    """Parse various ISO 8601 and WHOIS date formats into a datetime object."""
    if not date_str:
        return None
    # Strip trailing Z or offsets
    date_str = date_str.strip()
    formats = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d-%b-%Y",
        "%Y.%m.%d",
        "%d/%m/%Y"
    ]
    for fmt in formats:
        try:
            return datetime.strptime(date_str[:19], fmt[:len(date_str[:19])]).replace(tzinfo=timezone.utc)
        except Exception:
            continue
    # Try regex fallback for YYYY-MM-DD
    match = re.search(r"(\d{4})-(\d{2})-(\d{2})", date_str)
    if match:
        try:
            return datetime(int(match.group(1)), int(match.group(2)), int(match.group(3)), tzinfo=timezone.utc)
        except Exception:
            pass
    return None


def query_rdap(domain: str) -> dict:
    """
    Query ICANN's standardized Registration Data Access Protocol (RDAP) via HTTPS.
    Returns structured registration events, registrar, and creation timestamps.
    """
    url = f"https://rdap.org/domain/{domain}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "PhishTracker-RDAP-Client/1.0", "Accept": "application/rdap+json,application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                return data
    except Exception:
        pass
    return {}


def query_whois_socket(domain: str, whois_server: str = "whois.iana.org") -> str:
    """Fallback direct socket query on TCP port 43 for WHOIS servers."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((whois_server, 43))
        s.sendall(f"{domain}\r\n".encode("utf-8"))
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
            if len(response) > 32768:
                break
        s.close()
        return response.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def analyze_whois(hostname: str) -> dict:
    """
    Analyze domain registration metadata, age in days, and registrar info.
    """
    findings = []
    metadata = {
        "domain": "",
        "creation_date": None,
        "expiration_date": None,
        "age_days": None,
        "registrar": "Unknown",
        "status": []
    }

    # Extract base domain (e.g. sub.bank.example.com -> example.com)
    parts = hostname.split('.')
    if len(parts) >= 2:
        base_domain = f"{parts[-2]}.{parts[-1]}"
    else:
        base_domain = hostname

    metadata["domain"] = base_domain

    # 1. Attempt RDAP query
    rdap_data = query_rdap(base_domain)
    creation_date = None
    expiration_date = None
    registrar = "Unknown"

    if rdap_data:
        # Extract events
        events = rdap_data.get("events", [])
        for ev in events:
            action = ev.get("eventAction", "").lower()
            date_raw = ev.get("eventDate", "")
            if action in ["registration", "created"]:
                creation_date = parse_date_string(date_raw)
            elif action in ["expiration"]:
                expiration_date = parse_date_string(date_raw)

        # Extract entities / registrar
        entities = rdap_data.get("entities", [])
        for ent in entities:
            roles = ent.get("roles", [])
            if "registrar" in roles:
                vcard = ent.get("vcardArray", [])
                if len(vcard) > 1:
                    for field in vcard[1]:
                        if field[0] == "fn":
                            registrar = field[3]
                            break

    # 2. Fallback to socket WHOIS if RDAP had no creation date
    if not creation_date:
        raw_whois = query_whois_socket(base_domain)
        # Parse creation date from raw whois
        for line in raw_whois.splitlines():
            line_l = line.lower()
            if any(k in line_l for k in ["creation date:", "created:", "registered:"]):
                val = line.split(":", 1)[-1].strip()
                parsed = parse_date_string(val)
                if parsed:
                    creation_date = parsed
                    break
            if "registrar:" in line_l and registrar == "Unknown":
                registrar = line.split(":", 1)[-1].strip()

    # Calculate domain age
    if creation_date:
        metadata["creation_date"] = creation_date.strftime("%Y-%m-%d")
        now = datetime.now(timezone.utc)
        age_days = (now - creation_date).days
        metadata["age_days"] = max(0, age_days)

        if age_days < 30:
            findings.append({
                "id": "domain_age_under_30_days",
                "category": "Domain Intelligence",
                "title": f"Newly Registered Domain ({age_days} days old)",
                "description": f"Domain was registered on {metadata['creation_date']} ({age_days} days ago). Over 75% of phishing campaigns utilize domains registered < 30 days prior to attack launch.",
                "mitre": "T1583.001",
                "severity": "CRITICAL"
            })
        elif age_days < 90:
            findings.append({
                "id": "domain_age_under_90_days",
                "category": "Domain Intelligence",
                "title": f"Young Domain Infrastructure ({age_days} days old)",
                "description": f"Domain is relatively new ({age_days} days old). Established institutions typically operate domains registered for multiple years.",
                "mitre": "T1583.001",
                "severity": "MEDIUM"
            })

    if expiration_date:
        metadata["expiration_date"] = expiration_date.strftime("%Y-%m-%d")

    metadata["registrar"] = registrar

    return {
        "metadata": metadata,
        "findings": findings
    }
