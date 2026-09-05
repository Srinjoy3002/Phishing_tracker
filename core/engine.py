"""
PhishTracker Risk Scoring and Decision Engine.
Aggregates indicators across lexical, DNS, WHOIS, SSL, and DOM analyzers,
computes weighted risk scores, and generates MITRE ATT&CK mapped recommendations.
"""

from typing import Optional, Callable
from urllib.parse import urlparse
from core.config import (
    WEIGHTS,
    THRESHOLD_SAFE,
    THRESHOLD_SUSPICIOUS,
    THRESHOLD_MALICIOUS,
    MITRE_MAPPING
)
from core.lexical import analyze_lexical
from core.dns_intel import analyze_dns
from core.whois_intel import analyze_whois
from core.ssl_checker import analyze_ssl
from core.content_checker import analyze_content


def evaluate_threat_level(score: int) -> tuple[str, str, str]:
    """
    Returns (classification_name, color_tag, status_emoji) based on risk score.
    """
    if score >= THRESHOLD_MALICIOUS:
        return "CRITICAL PHISHING", "bold red", "🔴"
    elif score >= THRESHOLD_SUSPICIOUS:
        return "SUSPICIOUS", "bold yellow", "🟠"
    elif score >= THRESHOLD_SAFE:
        return "LOW RISK", "cyan", "🟡"
    else:
        return "BENIGN / SAFE", "bold green", "🟢"


def generate_recommendations(classification: str, findings: list[dict], hostname: str) -> list[str]:
    """
    Generate tailored SOC analyst / defensive incident response recommendations.
    """
    recs = []
    finding_ids = {f.get("id") for f in findings}

    if classification == "CRITICAL PHISHING":
        recs.append(f"⛔ Immediately BLOCK domain '{hostname}' on corporate DNS firewalls, EDR, and web proxies.")
        recs.append("🛡️ If users have interacted with this URL, trigger immediate credential reset and terminate active OAuth sessions.")
        recs.append("📢 Report domain to registrar abuse contacts and threat intelligence feeds (PhishTank, Google Safe Browsing).")
    elif classification == "SUSPICIOUS":
        recs.append(f"⚠️ Restrict access to '{hostname}' pending secondary manual triage by Security Operations (SOC).")
        recs.append("🔍 Review endpoint proxy logs to determine if any internal hosts resolved or contacted this domain.")
    else:
        recs.append("✅ No critical phishing signatures identified. Standard perimeter monitoring applies.")

    if "ssl_missing_or_failed" in finding_ids:
        recs.append("🔒 Advise users never to submit credentials or personal information over unencrypted or unverified HTTP.")
    if "content_password_external_form" in finding_ids:
        recs.append("🚨 Credential harvest signature detected: Web form exfiltrates data to external infrastructure.")
    if "idn_homograph" in finding_ids:
        recs.append("🔡 Punycode homograph attack detected. Ensure browser and email gateway Punycode-display policies are enabled.")

    return recs


def scan_target(
    target_url: str,
    fast_mode: bool = False,
    skip_content: bool = False,
    progress_callback: Optional[Callable[[str], None]] = None
) -> dict:
    """
    Orchestrate full multi-layer analysis of a target URL.
    """
    url = target_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    scheme = parsed.scheme.lower()

    all_findings = []
    
    # 1. Lexical Analysis
    if progress_callback:
        progress_callback("Executing URL lexical and syntactic heuristics...")
    lexical_res = analyze_lexical(url)
    all_findings.extend(lexical_res["findings"])
    brand_target = lexical_res["metrics"].get("brand_target")

    dns_res = {"data": {}, "findings": []}
    whois_res = {"metadata": {}, "findings": []}
    ssl_res = {"data": {}, "findings": []}
    content_res = {"data": {}, "findings": []}

    if not fast_mode:
        # 2. DNS Analysis
        if progress_callback:
            progress_callback(f"Resolving DNS records and evaluating infrastructure for {hostname}...")
        dns_res = analyze_dns(hostname, brand_target=brand_target)
        all_findings.extend(dns_res["findings"])

        # 3. WHOIS / RDAP Analysis
        if progress_callback:
            progress_callback(f"Querying RDAP / WHOIS domain age telemetry...")
        whois_res = analyze_whois(hostname)
        all_findings.extend(whois_res["findings"])

        # 4. SSL / TLS Analysis
        if progress_callback:
            progress_callback(f"Inspecting SSL/TLS cryptographic certificates...")
        ssl_res = analyze_ssl(hostname, scheme=scheme, brand_target=brand_target)
        all_findings.extend(ssl_res["findings"])

        # 5. Passive Content Inspection
        if not skip_content:
            if progress_callback:
                progress_callback(f"Conducting safe passive HTML / DOM inspection...")
            content_res = analyze_content(url, hostname, brand_target=brand_target)
            all_findings.extend(content_res["findings"])

    # Calculate Cumulative Risk Score
    raw_score = 0
    for finding in all_findings:
        fid = finding.get("id", "")
        weight = WEIGHTS.get(fid)
        if weight is None:
            # Fallback based on severity
            sev = finding.get("severity", "LOW")
            weight = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 12, "LOW": 5}.get(sev, 5)
        raw_score += weight

    # Deduplicate findings with same ID
    unique_findings = []
    seen_ids = set()
    for f in all_findings:
        if f["id"] not in seen_ids:
            # Enrich with MITRE ATT&CK details
            mitre_id = f.get("mitre")
            if mitre_id and mitre_id in MITRE_MAPPING:
                f["mitre_name"] = MITRE_MAPPING[mitre_id]["name"]
                f["mitre_desc"] = MITRE_MAPPING[mitre_id]["description"]
            unique_findings.append(f)
            seen_ids.add(f["id"])

    # Final normalized score capped at 100
    final_score = min(100, raw_score)
    classification, color_tag, emoji = evaluate_threat_level(final_score)
    recommendations = generate_recommendations(classification, unique_findings, hostname)

    return {
        "url": target_url,
        "hostname": hostname,
        "scheme": scheme,
        "risk_score": final_score,
        "classification": classification,
        "color_tag": color_tag,
        "emoji": emoji,
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
