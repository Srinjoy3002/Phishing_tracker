"""
Lexical and URL structure heuristic analyzer.
Performs zero-latency static analysis on the URL string.
Includes reverse-tunnel detection and deceptive URL-masking extraction.
"""

import math
import re
import ipaddress
from urllib.parse import urlparse, unquote
from core.config import (
    SUSPICIOUS_TLDS,
    TARGETED_BRANDS,
    SENSITIVE_KEYWORDS,
    URL_SHORTENERS,
    REVERSE_TUNNEL_SERVICES
)


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
    clean_host = host.split(':')[0].strip('[]')
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        pass

    if re.match(r"^0x[0-9a-fA-F]+$", clean_host):
        return True
    if clean_host.isdigit() and int(clean_host) > 0:
        return True
        
    return False


def check_punycode_homograph(host: str) -> tuple[bool, str]:
    """Detects Punycode (xn--) and IDN Homograph attacks."""
    if "xn--" in host.lower():
        try:
            decoded = host.encode("utf-8").decode("idna")
            return True, f"Punycode encoded domain detected: '{host}' (Resolves visually to: '{decoded}')"
        except Exception:
            return True, f"Punycode domain detected: '{host}'"
            
    non_ascii = [c for c in host if ord(c) > 127]
    if non_ascii:
        return True, f"Non-ASCII homograph characters present in domain: {set(non_ascii)}"
        
    return False, ""


def check_reverse_tunnel(host: str) -> tuple[bool, str]:
    """
    Detects if the hostname is hosted on a reverse-tunneling or port-forwarding service
    (Cloudflare Quick Tunnels, Ngrok, Localtunnel, Serveo, etc.)
    used heavily by automated phishing frameworks (PyPhisher, Zphisher).
    """
    host_lower = host.lower()
    for tunnel_domain in REVERSE_TUNNEL_SERVICES:
        if host_lower == tunnel_domain or host_lower.endswith("." + tunnel_domain):
            return True, tunnel_domain
    return False, ""


def check_brand_spoofing(host: str) -> tuple[bool, str, str]:
    """
    Detects combosquatting where a known brand is in the hostname
    while not belonging to the official domain.
    """
    host_lower = host.lower()
    
    for brand, legit_domains in TARGETED_BRANDS.items():
        if brand in host_lower:
            is_legit = False
            for legit in legit_domains:
                if host_lower == legit or host_lower.endswith("." + legit):
                    is_legit = True
                    break
            
            if not is_legit:
                return True, brand, f"Brand impersonation: Hostname references '{brand.upper()}' but does not belong to authorized domains ({', '.join(legit_domains)})"
                
    return False, "", ""


def analyze_lexical(raw_url: str) -> dict:
    """
    Comprehensive lexical and syntactic analysis of the URL.
    Returns detected indicators, metric values, and raw parsed components.
    """
    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path
    query = parsed.query
    netloc = parsed.netloc
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
        "brand_target": None,
        "is_reverse_tunnel": False,
        "tunnel_provider": None,
        "masked_bait": None
    }

    # 1. Reverse Tunnel / Ephemeral Hosting Detection (PyPhisher / Ngrok / Cloudflare Quick Tunnels)
    is_tunnel, tunnel_svc = check_reverse_tunnel(hostname)
    if is_tunnel:
        metrics["is_reverse_tunnel"] = True
        metrics["tunnel_provider"] = tunnel_svc
        findings.append({
            "id": "reverse_tunnel_service",
            "category": "Tunnel Infrastructure",
            "title": f"Ephemeral Reverse Tunnel Host ({tunnel_svc})",
            "description": f"Domain is hosted via '{tunnel_svc}'. Ephemeral reverse-tunnels (Cloudflare Tunnels, Ngrok, Localtunnel) are the #1 infrastructure vector weaponized by automated phishing tools (PyPhisher, Zphisher).",
            "mitre": "T1585",
            "severity": "HIGH"
        })

        # Check for Cloudflare Quick Tunnel 4-word random subdomain pattern
        # e.g., occupation-exposure-piece-spam.trycloudflare.com
        subdomain_part = hostname.replace("." + tunnel_svc, "")
        hyphen_parts = subdomain_part.split("-")
        if len(hyphen_parts) >= 3:
            findings.append({
                "id": "tunnel_random_subdomains",
                "category": "Tunnel Infrastructure",
                "title": f"Auto-Generated Tunnel Subdomain ({len(hyphen_parts)} words)",
                "description": f"Subdomain '{subdomain_part}' follows automated random multi-word naming format (e.g. Cloudflare Quick Tunnels generated by PyPhisher).",
                "mitre": "T1583.001",
                "severity": "HIGH"
            })

    # 2. Deceptive URL Masking & Bait Extraction (@ sign)
    if "@" in netloc:
        bait_part, actual_host = netloc.split("@", 1)
        bait_decoded = unquote(bait_part)
        metrics["masked_bait"] = bait_decoded

        findings.append({
            "id": "url_redirection_trick",
            "category": "Lexical",
            "title": "Deceptive URL Masking Trick ('@' symbol)",
            "description": f"RFC 3986 redirection exploit: Browsers ignore the prefix '{bait_decoded}' and silently route traffic to '{actual_host}'.",
            "mitre": "T1566.002",
            "severity": "CRITICAL"
        })

        # Analyze the bait string itself for brand masquerading or lures
        bait_lower = bait_decoded.lower()
        matched_bait_brands = [b for b in TARGETED_BRANDS if b in bait_lower]
        matched_bait_kws = [k for k in SENSITIVE_KEYWORDS if k in bait_lower]

        if matched_bait_brands or matched_bait_kws:
            brand_str = f"targeting {', '.join(matched_bait_brands).upper()}" if matched_bait_brands else ""
            findings.append({
                "id": "url_masked_bait",
                "category": "Lexical",
                "title": f"Weaponized Masking Bait ({brand_str})",
                "description": f"The bait text '{bait_decoded}' masquerades as legitimate services to trick the victim into clicking.",
                "mitre": "T1566.002",
                "severity": "CRITICAL"
            })
            if matched_bait_brands and not metrics["brand_target"]:
                metrics["brand_target"] = matched_bait_brands[0]

    # 3. IP Address Hostname
    if is_ip_address(hostname):
        findings.append({
            "id": "ip_in_url",
            "category": "Lexical",
            "title": "IP Address Used in Hostname",
            "description": f"URL uses raw IP '{hostname}' instead of a legitimate domain name to evade domain registration scrutiny.",
            "mitre": "T1566.002",
            "severity": "HIGH"
        })

    # 4. Homograph / Punycode
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

    # 5. Domain Shannon Entropy
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

    # 6. Brand Impersonation / Combosquatting
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

    # 7. Top-Level Domain (TLD) Analysis
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

    # 8. Subdomain Depth
    subdomain_count = max(0, len(domain_parts) - 2)
    metrics["subdomain_count"] = subdomain_count
    if subdomain_count >= 3 and not is_tunnel:
        findings.append({
            "id": "excessive_subdomains",
            "category": "Lexical",
            "title": f"Excessive Subdomain Depth ({subdomain_count} levels)",
            "description": f"Deep subdomain nesting is frequently used to push the attacker's actual domain off-screen on mobile devices.",
            "mitre": "T1566.002",
            "severity": "MEDIUM"
        })

    # 9. Double Slash Redirection in Path
    if "//" in path:
        findings.append({
            "id": "double_slash_redirect",
            "category": "Lexical",
            "title": "Double Slash '//' in URL Path",
            "description": "Double slash pattern in path can exploit open-redirect vulnerabilities in web servers.",
            "mitre": "T1566.002",
            "severity": "LOW"
        })

    # 10. Excessive Hyphens (if not a tunnel where hyphens are already flagged)
    hyphen_count = hostname.count("-")
    if hyphen_count >= 3 and not is_tunnel:
        findings.append({
            "id": "excessive_hyphens",
            "category": "Lexical",
            "title": f"Excessive Hyphens in Domain ({hyphen_count} hyphens)",
            "description": "Phishers commonly concatenate legitimate brand terms with hyphens (combosquatting).",
            "mitre": "T1583.001",
            "severity": "MEDIUM"
        })

    # 11. URL Length
    if len(full_url) > 85:
        findings.append({
            "id": "url_length_excessive",
            "category": "Lexical",
            "title": f"Excessive URL Length ({len(full_url)} characters)",
            "description": "Abnormally long URLs are frequently used to conceal the destination or embed payloads.",
            "mitre": "T1566.002",
            "severity": "LOW"
        })

    # 12. Sensitive Phishing Keywords
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

    # 13. Known URL Shortener
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
