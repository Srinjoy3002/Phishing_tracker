"""
DNS Telemetry and Network Infrastructure Analyzer.
Performs live DNS resolution, MX validation, and Fast-Flux detection.
"""

import socket
import ipaddress
from typing import Optional
import dns.resolver
from core.config import TARGETED_BRANDS


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address belongs to RFC 1918 private/loopback/link-local ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def get_reverse_dns(ip_str: str) -> Optional[str]:
    """Perform reverse DNS (PTR) lookup for an IP address."""
    try:
        host, _, _ = socket.gethostbyaddr(ip_str)
        return host
    except Exception:
        return None


def analyze_dns(hostname: str, brand_target: Optional[str] = None) -> dict:
    """
    Perform DNS reconnaissance and assess infrastructure indicators.
    """
    findings = []
    dns_data = {
        "resolved": False,
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "ttl": None,
        "reverse_dns": None,
        "is_private": False
    }

    # Clean hostname (strip port if present)
    clean_host = hostname.split(':')[0].strip('[]')

    # If already an IP address, we don't need full domain DNS resolution
    try:
        ipaddress.ip_address(clean_host)
        dns_data["resolved"] = True
        dns_data["a_records"] = [clean_host]
        dns_data["reverse_dns"] = get_reverse_dns(clean_host)
        if is_private_ip(clean_host):
            dns_data["is_private"] = True
            findings.append({
                "id": "private_ip_redirection",
                "category": "DNS & Network",
                "title": "Private / RFC 1918 Loopback IP",
                "description": f"Target points to internal/private IP '{clean_host}'. Often used in SSRF or internal intranet phishing.",
                "mitre": "T1584.004",
                "severity": "HIGH"
            })
        return {"data": dns_data, "findings": findings}
    except ValueError:
        pass

    # Configure DNS resolver
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.5
    resolver.lifetime = 2.5
    # Add public DNS fallbacks if default is unpopulated
    if not resolver.nameservers:
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]

    # 1. Resolve A Records (IPv4)
    # First attempt dnspython to capture TTL
    try:
        answers = resolver.resolve(clean_host, "A")
        for rdata in answers:
            dns_data["a_records"].append(str(rdata))
        if answers.rrset:
            dns_data["ttl"] = answers.rrset.ttl
    except Exception:
        # Fallback to public DNS
        try:
            fallback_resolver = dns.resolver.Resolver(configure=False)
            fallback_resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
            fallback_resolver.timeout = 2.0
            fallback_resolver.lifetime = 2.0
            answers = fallback_resolver.resolve(clean_host, "A")
            for rdata in answers:
                dns_data["a_records"].append(str(rdata))
            if answers.rrset:
                dns_data["ttl"] = answers.rrset.ttl
        except Exception:
            pass

    # Native OS socket resolution fallback (guaranteed to match OS routing)
    if not dns_data["a_records"]:
        try:
            addr_info = socket.getaddrinfo(clean_host, None, socket.AF_INET)
            for item in addr_info:
                ip = item[4][0]
                if ip not in dns_data["a_records"]:
                    dns_data["a_records"].append(ip)
        except Exception:
            pass

    if dns_data["a_records"]:
        dns_data["resolved"] = True
        first_ip = dns_data["a_records"][0]
        dns_data["reverse_dns"] = get_reverse_dns(first_ip)
        if is_private_ip(first_ip):
            dns_data["is_private"] = True
            findings.append({
                "id": "private_ip_redirection",
                "category": "DNS & Network",
                "title": "Resolves to Private / Loopback IP",
                "description": f"Domain resolves to internal address {first_ip}.",
                "mitre": "T1584.004",
                "severity": "HIGH"
            })

        # Fast-Flux check: low TTL with multiple IPs
        if dns_data["ttl"] and dns_data["ttl"] < 60 and len(dns_data["a_records"]) >= 3:
            findings.append({
                "id": "fast_flux_dns",
                "category": "DNS & Network",
                "title": f"Fast-Flux DNS Behavior (TTL: {dns_data['ttl']}s)",
                "description": f"Rapidly cycling IP addresses with extremely short TTL ({dns_data['ttl']}s) detected. Hallmark of botnet-hosted phishing sites.",
                "mitre": "T1584.004",
                "severity": "HIGH"
            })
    else:
        dns_data["resolved"] = False
        findings.append({
            "id": "dns_no_a_record",
            "category": "DNS & Network",
            "title": "Domain Resolution Failure (No A Record)",
            "description": f"Could not resolve A record for '{clean_host}'. The domain may be abandoned, sinkholed, or newly generated.",
            "mitre": "T1584.004",
            "severity": "MEDIUM"
        })


    # 2. Query AAAA Records (IPv6)
    try:
        answers = resolver.resolve(clean_host, "AAAA")
        for rdata in answers:
            dns_data["aaaa_records"].append(str(rdata))
    except Exception:
        pass

    # 3. Query MX Records (Mail Exchange)
    try:
        answers = resolver.resolve(clean_host, "MX")
        for rdata in answers:
            dns_data["mx_records"].append(str(rdata.exchange).rstrip('.'))
    except Exception:
        pass

    # MX Record Check: If domain is impersonating a brand or financial firm but has zero MX records
    if dns_data["resolved"] and not dns_data["mx_records"] and brand_target:
        findings.append({
            "id": "dns_missing_mx_branded",
            "category": "DNS & Network",
            "title": f"Missing MX Records on Spoofed Brand ({brand_target.upper()})",
            "description": f"Domain references high-profile brand '{brand_target.upper()}' but maintains no Mail Exchange (MX) records. Legitimate organizations always have mail routing infrastructure configured.",
            "mitre": "T1584.004",
            "severity": "HIGH"
        })

    # 4. Query NS Records
    try:
        answers = resolver.resolve(clean_host, "NS")
        for rdata in answers:
            dns_data["ns_records"].append(str(rdata.target).rstrip('.'))
    except Exception:
        pass

    # 5. Query TXT Records (Check SPF/DMARC)
    try:
        answers = resolver.resolve(clean_host, "TXT")
        for rdata in answers:
            txt_str = "".join([part.decode("utf-8", errors="ignore") for part in rdata.strings])
            dns_data["txt_records"].append(txt_str[:120])
    except Exception:
        pass

    return {
        "data": dns_data,
        "findings": findings
    }
