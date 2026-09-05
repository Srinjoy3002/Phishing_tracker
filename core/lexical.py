"""
Lexical and URL structure heuristic analyzer.
Performs zero-latency static analysis on the URL string.
"""

import math
import re
import ipaddress
from urllib.parse import urlparse, unquote
from core.config import SUSPICIOUS_TLDS, TARGETED_BRANDS, SENSITIVE_KEYWORDS, URL_SHORTENERS


def calculate_entropy(text: str) -> float:
    """Calculate Shannon Entropy of a string to detect random DGA or obfuscated domains."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def is_ip_address(host: str) -> bool:
    """Check if the hostname is a direct IPv4, IPv6, or integer/hex obfuscated IP."""
    # Strip port if present
    clean_host = host.split(':')[0].strip('[]')
    
    # Standard IPv4 or IPv6
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        pass

    # Hexadecimal IP (e.g., 0x7f000001) or pure numeric DWORD IP
    if re.match(r"^0x[0-9a-fA-F]+$", clean_host):
        return True
    if clean_host.isdigit() and int(clean_host) > 0:
        return True
        
    return False


def check_punycode_homograph(host: str) -> tuple[bool, str]:
    """
    Detects Punycode (xn--) and IDN Homograph attacks where non-Latin lookalike
    characters (Cyrillic, Greek) are used to impersonate legitimate characters.
    """
    if "xn--" in host.lower():
        try:
            decoded = host.encode("utf-8").decode("idna")
            return True, f"Punycode encoded domain detected: '{host}' (Resolves visually to: '{decoded}')"
        except Exception:
            return True, f"Punycode domain detected: '{host}'"
            
    # Check for mixed script or non-ASCII characters directly
    non_ascii = [c for c in host if ord(c) > 127]
    if non_ascii:
        return True, f"Non-ASCII homograph characters present in domain: {set(non_ascii)}"
        
    return False, ""


def check_brand_spoofing(host: str) -> tuple[bool, str, str]:
    """
    Detects combosquatting and typosquatting where a well-known brand is embedded
    in the subdomain or domain name while belonging to an unverified entity.
    """
    host_lower = host.lower()
    
    for brand, legit_domains in TARGETED_BRANDS.items():
        # Check if the brand name is present anywhere in the hostname
        if brand in host_lower:
            # Check if it matches any official legitimate domain
            is_legit = False
            for legit in legit_domains:
                if host_lower == legit or host_lower.endswith("." + legit):
                    is_legit = True
                    break
            
            if not is_legit:
                return True, brand, f"Brand impersonation detected: Hostname references '{brand.upper()}' but does not belong to authorized domains ({', '.join(legit_domains)})"
                
    return False, "", ""


def analyze_lexical(raw_url: str) -> dict:
    """
    Comprehensive lexical and syntactic analysis of the URL.
    Returns detected indicators, metric values, and raw parsed components.
    """
    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url  # default schema for parsing

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path
    query = parsed.query
    full_url = raw_url.strip()

    findings = []
    metrics = {
        "raw_url": raw_url,
        "hostname": hostname,
        "scheme": parsed.scheme,
        "path": path,
        "entropy": 0.0,
        "url_length": len(full_url),
        "subdomain_count": 0,
        "tld": "",
        "brand_target": None
    }

    # 1. IP Address Hostname
    if is_ip_address(hostname):
        findings.append({
            "id": "ip_in_url",
            "category": "Lexical",
            "title": "IP Address Used in Hostname",
            "description": f"URL uses raw IP '{hostname}' instead of a legitimate domain name to evade domain registration scrutiny.",
            "mitre": "T1566.002",
            "severity": "HIGH"
        })

    # 2. Homograph / Punycode
    is_homograph, homograph_msg = check_punycode_homograph(hostname)
    if is_homograph:
        findings.append({
            "id": "idn_homograph",
            "category": "Lexical",
            "title": "IDN Homograph / Punycode Obfuscation",
            "description": homograph_msg,
            "mitre": "T1583.001",
            "severity": "CRITICAL"
        })

    # 3. Domain Shannon Entropy
    domain_parts = hostname.split('.')
    main_domain = domain_parts[-2] if len(domain_parts) >= 2 else hostname
    entropy = calculate_entropy(main_domain)
    metrics["entropy"] = entropy
    if entropy >= 3.8 and len(main_domain) >= 8:
        findings.append({
            "id": "high_entropy_domain",
            "category": "Lexical",
            "title": f"High Domain Entropy ({entropy})",
            "description": f"Main domain '{main_domain}' exhibits high Shannon entropy, indicating possible Domain Generation Algorithm (DGA) or machine-generated random string.",
            "mitre": "T1584.004",
            "severity": "MEDIUM"
        })

    # 4. Brand Impersonation / Combosquatting
    is_spoof, brand, spoof_msg = check_brand_spoofing(hostname)
    if is_spoof:
        metrics["brand_target"] = brand
        findings.append({
            "id": "brand_spoofing",
            "category": "Lexical",
            "title": f"Brand Spoofing: {brand.upper()}",
            "description": spoof_msg,
            "mitre": "T1566.002",
            "severity": "CRITICAL"
        })

    # 5. Top-Level Domain (TLD) Analysis
    if len(domain_parts) >= 2:
        tld = domain_parts[-1].lower()
        metrics["tld"] = tld
        if tld in SUSPICIOUS_TLDS:
            findings.append({
                "id": "suspicious_tld",
                "category": "Lexical",
                "title": f"Suspicious High-Abuse TLD (.{tld})",
                "description": f"The top-level domain '.{tld}' has a statistically elevated abuse score in global threat telemetry.",
                "mitre": "T1583.001",
                "severity": "MEDIUM"
            })

    # 6. Subdomain Depth
    # e.g., login.verification.bank.attacker.com has 4 dots
    subdomain_count = max(0, len(domain_parts) - 2)
    metrics["subdomain_count"] = subdomain_count
    if subdomain_count >= 3:
        findings.append({
            "id": "excessive_subdomains",
            "category": "Lexical",
            "title": f"Excessive Subdomain Depth ({subdomain_count} levels)",
            "description": f"Deep subdomain nesting is frequently used to push the attacker's actual domain off-screen on mobile devices.",
            "mitre": "T1566.002",
            "severity": "MEDIUM"
        })

    # 7. Redirection Trick (@ symbol in authority)
    if "@" in parsed.netloc:
        findings.append({
            "id": "url_redirection_trick",
            "category": "Lexical",
            "title": "URL Authority Redirection Trick ('@' symbol)",
            "description": "RFC 3986 authority trick: Browsers treat characters before '@' as user credentials and route traffic to the domain following the '@'.",
            "mitre": "T1566.002",
            "severity": "CRITICAL"
        })

    # 8. Double Slash Redirection in Path
    if "//" in path:
        findings.append({
            "id": "double_slash_redirect",
            "category": "Lexical",
            "title": "Double Slash '//' in URL Path",
            "description": "Double slash pattern in path can exploit open-redirect vulnerabilities in web servers.",
            "mitre": "T1566.002",
            "severity": "LOW"
        })

    # 9. Excessive Hyphens
    hyphen_count = hostname.count("-")
    if hyphen_count >= 3:
        findings.append({
            "id": "excessive_hyphens",
            "category": "Lexical",
            "title": f"Excessive Hyphens in Domain ({hyphen_count} hyphens)",
            "description": "Phishers commonly concatenate legitimate brand terms with hyphens (combosquatting).",
            "mitre": "T1583.001",
            "severity": "MEDIUM"
        })

    # 10. URL Length
    if len(full_url) > 85:
        findings.append({
            "id": "url_length_excessive",
            "category": "Lexical",
            "title": f"Excessive URL Length ({len(full_url)} characters)",
            "description": "Abnormally long URLs are frequently used to conceal the destination or embed base64/hex payloads.",
            "mitre": "T1566.002",
            "severity": "LOW"
        })

    # 11. Sensitive Phishing Keywords
    matched_keywords = []
    combined_target = (hostname + path + query).lower()
    for kw in SENSITIVE_KEYWORDS:
        if kw in combined_target:
            matched_keywords.append(kw)
            
    if len(matched_keywords) >= 2:
        findings.append({
            "id": "sensitive_keywords",
            "category": "Lexical",
            "title": f"Credential / Lure Keywords Detected ({', '.join(matched_keywords[:4])})",
            "description": f"URL contains multiple high-risk credential harvesting keywords: {', '.join(matched_keywords)}",
            "mitre": "T1566.002",
            "severity": "MEDIUM"
        })

    # 12. Known URL Shortener
    if hostname in URL_SHORTENERS:
        findings.append({
            "id": "url_shortener",
            "category": "Lexical",
            "title": f"URL Shortener Service ({hostname})",
            "description": "URL shorteners obscure the final landing destination and are widely used in smishing and spearphishing.",
            "mitre": "T1566.002",
            "severity": "LOW"
        })

    return {
        "metrics": metrics,
        "findings": findings
    }
