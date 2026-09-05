"""
PhishTracker Risk Scoring and Decision Engine with OPSEC Anonymity Controller.
Aggregates indicators across lexical, reverse-tunnel, DNS, WHOIS, SSL, and DOM analyzers.
Enforces compound heuristic overrides for automated phishing kits (PyPhisher, Zphisher).
"""

import socket
from typing import Optional, Callable
from urllib.parse import urlparse
from core.config import (
    WEIGHTS,
    THRESHOLD_SAFE,
    THRESHOLD_SUSPICIOUS,
    THRESHOLD_MALICIOUS,
    MITRE_MAPPING,
    TOR_PROXIES
)
from core.lexical import analyze_lexical
from core.dns_intel import analyze_dns
from core.whois_intel import analyze_whois
from core.ssl_checker import analyze_ssl
from core.content_checker import analyze_content


def check_local_tor_port(port: int) -> bool:
    """Check if a local Tor SOCKS5 proxy port is active and accepting connections."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        res = s.connect_ex(('127.0.0.1', port))
        s.close()
        return res == 0
    except Exception:
        return False


def get_proxy_configuration(proxy_arg: Optional[str], use_tor: bool) -> tuple[Optional[dict], str]:
    """
    Determine proxy configuration and return (proxies_dict, opsec_mode_label).
    """
    if proxy_arg:
        p_dict = {"http": proxy_arg, "https": proxy_arg}
        return p_dict, f"PROXY PROTECTED ({proxy_arg})"

    if use_tor:
        # Check standard Tor daemon port (9050) then Tor Browser port (9150)
        if check_local_tor_port(9050):
            return {"http": TOR_PROXIES["standard"], "https": TOR_PROXIES["standard"]}, "TOR ANONYMIZED (Port 9050)"
        elif check_local_tor_port(9150):
            return {"http": TOR_PROXIES["browser"], "https": TOR_PROXIES["browser"]}, "TOR ANONYMIZED (Tor Browser 9150)"
        else:
            # Tor requested but not listening locally
            return None, "TOR UNAVAILABLE (Local Tor daemon not detected on 9050/9150)"

    return None, "DIRECT CONNECTION (Source IP Exposed)"


def evaluate_threat_level(score: int) -> tuple[str, str, str]:
    """Returns (classification_name, color_tag, status_emoji) based on risk score."""
    if score >= THRESHOLD_MALICIOUS:
        return "CRITICAL PHISHING", "bold red", "🔴"
    elif score >= THRESHOLD_SUSPICIOUS:
        return "SUSPICIOUS", "bold yellow", "🟠"
    elif score >= THRESHOLD_SAFE:
        return "LOW RISK", "cyan", "🟡"
    else:
        return "BENIGN / SAFE", "bold green", "🟢"


def generate_recommendations(classification: str, findings: list[dict], hostname: str, opsec_label: str) -> list[str]:
    """Generate tailored SOC analyst recommendations and OPSEC warnings."""
    recs = []
    finding_ids = {f.get("id") for f in findings}

    if classification == "CRITICAL PHISHING":
        recs.append(f"⛔ Immediately BLOCK domain/tunnel '{hostname}' across perimeter firewalls, proxies, and EDR.")
        recs.append("🚨 High-confidence credential harvester detected (PyPhisher/Zphisher kit pattern).")
        recs.append("📢 Submit domain to Cloudflare Abuse / Registrar / PhishTank for immediate tunnel teardown.")
    elif classification == "SUSPICIOUS":
        recs.append(f"⚠️ Restrict access to '{hostname}' pending secondary manual triage by Security Operations (SOC).")
        recs.append("🔍 Review endpoint proxy logs to determine if any internal users resolved or visited this target.")
    else:
        recs.append("✅ No critical phishing signatures identified. Standard perimeter monitoring applies.")

    # OPSEC specific guidance
    if "victim_tracking_script" in finding_ids:
        if "DIRECT" in opsec_label:
            recs.append("⚠️ OPSEC COMPROMISE WARNING: The target site runs an active IP logger (ip-api.com). Because this scan ran in Direct mode, your source IP and approximate location were recorded by the phishing server!")
            recs.append("🛡️ For future scans of active phishing sites, route through Tor (--tor) or a VPN/Proxy (--proxy) to stay anonymous.")
        else:
            recs.append("🛡️ OPSEC PROTECTED: The phishing site attempted to log your IP via ip-api.com, but only captured your proxy/Tor exit node IP.")

    if "reverse_tunnel_service" in finding_ids:
        recs.append("🌐 Cloudflare/Ngrok Quick Tunnel detected: Ephemeral infrastructure will typically expire once the attacker's terminal closes.")
    if "url_masked_bait" in finding_ids:
        recs.append("🔡 Deceptive URL masking lure (@ trick) identified. Educate staff against clicking links with misleading prefixes.")

    return recs


def scan_target(
    target_url: str,
    fast_mode: bool = False,
    skip_content: bool = False,
    proxy: Optional[str] = None,
    use_tor: bool = False,
    progress_callback: Optional[Callable[[str], None]] = None
) -> dict:
    """
    Orchestrate full multi-layer analysis of a target URL with OPSEC controls.
    """
    url = target_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    scheme = parsed.scheme.lower()

    # Determine proxy & OPSEC status
    proxies_dict, opsec_label = get_proxy_configuration(proxy, use_tor)

    all_findings = []
    
    # 1. Lexical & URL Masking Analysis (Offline, Zero IP footprint)
    if progress_callback:
        progress_callback("Executing URL lexical, reverse-tunnel, and masking heuristics...")
    lexical_res = analyze_lexical(url)
    all_findings.extend(lexical_res["findings"])
    
    brand_target = lexical_res["metrics"].get("brand_target")
    is_reverse_tunnel = lexical_res["metrics"].get("is_reverse_tunnel", False)

    dns_res = {"data": {}, "findings": []}
    whois_res = {"metadata": {}, "findings": []}
    ssl_res = {"data": {}, "findings": []}
    content_res = {"data": {}, "findings": []}

    if not fast_mode:
        # 2. DNS Infrastructure Analysis
        if progress_callback:
            progress_callback(f"Resolving DNS records and evaluating infrastructure for {hostname}...")
        dns_res = analyze_dns(hostname, brand_target=brand_target)
        all_findings.extend(dns_res["findings"])

        # 3. WHOIS / RDAP Analysis (Skips RDAP for known ephemeral tunnels to avoid unnecessary queries)
        if not is_reverse_tunnel:
            if progress_callback:
                progress_callback("Querying RDAP / WHOIS domain age telemetry...")
            whois_res = analyze_whois(hostname)
            all_findings.extend(whois_res["findings"])

        # 4. SSL / TLS Analysis
        if progress_callback:
            progress_callback("Inspecting SSL/TLS cryptographic certificates...")
        ssl_res = analyze_ssl(hostname, scheme=scheme, brand_target=brand_target)
        all_findings.extend(ssl_res["findings"])

        # 5. Passive Content Inspection (With OPSEC Proxy Protection)
        if not skip_content:
            if progress_callback:
                progress_callback(f"Conducting safe passive DOM inspection ({opsec_label})...")
            content_res = analyze_content(
                target_url=url,
                hostname=hostname,
                brand_target=brand_target,
                is_reverse_tunnel=is_reverse_tunnel,
                proxies=proxies_dict
            )
            all_findings.extend(content_res["findings"])

    # Calculate Cumulative Risk Score
    raw_score = 0
    for finding in all_findings:
        fid = finding.get("id", "")
        weight = WEIGHTS.get(fid)
        if weight is None:
            sev = finding.get("severity", "LOW")
            weight = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 12, "LOW": 5}.get(sev, 5)
        raw_score += weight

    # Deduplicate findings
    unique_findings = []
    seen_ids = set()
    for f in all_findings:
        if f["id"] not in seen_ids:
            mitre_id = f.get("mitre")
            if mitre_id and mitre_id in MITRE_MAPPING:
                f["mitre_name"] = MITRE_MAPPING[mitre_id]["name"]
                f["mitre_desc"] = MITRE_MAPPING[mitre_id]["description"]
            unique_findings.append(f)
            seen_ids.add(f["id"])

    # COMPOUND HIGH-CONFIDENCE HEURISTIC OVERRIDE:
    # If target is on a Reverse Tunnel (trycloudflare, ngrok, loca.lt) AND has:
    # (Password form OR phishing kit endpoint OR brand spoofing OR masked bait)
    # -> It is 100% an active phishing kit (PyPhisher / Zphisher) operation!
    has_kit_signature = any(f["id"] in [
        "reverse_tunnel_with_login",
        "phishing_kit_endpoint",
        "content_password_external_form",
        "url_masked_bait",
        "victim_tracking_script"
    ] for f in unique_findings)

    if is_reverse_tunnel and (has_kit_signature or brand_target):
        final_score = max(95, min(100, raw_score))
    else:
        final_score = min(100, raw_score)

    classification, color_tag, emoji = evaluate_threat_level(final_score)
    recommendations = generate_recommendations(classification, unique_findings, hostname, opsec_label)

    return {
        "url": target_url,
        "hostname": hostname,
        "scheme": scheme,
        "risk_score": final_score,
        "classification": classification,
        "color_tag": color_tag,
        "emoji": emoji,
        "opsec_mode": opsec_label,
        "findings_count": len(unique_findings),
        "findings": unique_findings,
        "recommendations": recommendations,
        "telemetry": {
            "lexical": lexical_res["metrics"],
            "dns": dns_res["data"],
            "whois": whois_res["metadata"],
            "ssl": ssl_res["data"],
            "content": content_res["data"]
        }
    }
