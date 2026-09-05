"""
Passive HTML and DOM Security Inspector.
Safely extracts credential forms, title-brand divergence, hidden iframes, and anti-analysis scripts.
NEVER executes JavaScript or loads remote active content.
"""

import re
from urllib.parse import urljoin, urlparse
from typing import Optional
import requests
from core.config import SAFE_USER_AGENT, REQUEST_TIMEOUT, TARGETED_BRANDS


def analyze_content(target_url: str, hostname: str, brand_target: Optional[str] = None) -> dict:
    """
    Perform safe, non-executing passive content inspection on the target URL.
    """
    findings = []
    content_data = {
        "status_code": None,
        "title": "None",
        "redirect_history": [],
        "has_password_field": False,
        "external_form_action": None,
        "security_headers_missing": [],
        "inspected": False,
        "error": None
    }

    headers = {
        "User-Agent": SAFE_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    try:
        response = requests.get(
            target_url,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            verify=False  # Do not drop inspection if cert is self-signed/invalid
        )
        content_data["inspected"] = True
        content_data["status_code"] = response.status_code

        # Track redirect hops
        if response.history:
            content_data["redirect_history"] = [r.url for r in response.history]

        # Limit body inspection to first 500 KB to guard against resource exhaustion
        body = response.text[:500000]

        # 1. Page Title Extraction & Brand Divergence Check
        title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        if title_match:
            page_title = title_match.group(1).strip()
            content_data["title"] = page_title[:100]

            # Check if title claims to be a brand while the domain is unrelated
            for brand, legit_domains in TARGETED_BRANDS.items():
                if brand in page_title.lower():
                    # Check if actual hostname belongs to legitimate domains
                    is_official = any(hostname == dom or hostname.endswith("." + dom) for dom in legit_domains)
                    if not is_official:
                        findings.append({
                            "id": "content_title_brand_mismatch",
                            "category": "HTML / DOM Content",
                            "title": f"Title Brand Mismatch: Claims '{brand.upper()}'",
                            "description": f"Page title claims to be '{page_title}' ({brand.upper()}), but is hosted on unauthorized domain '{hostname}'. Strong phishing signature.",
                            "mitre": "T1566.002",
                            "severity": "CRITICAL"
                        })
                        break

        # 2. Form & Credential Harvesting Analysis
        # Check if password input exists
        has_password = bool(re.search(r'<input[^>]+type=["\']password["\']', body, re.IGNORECASE))
        content_data["has_password_field"] = has_password

        # Find all forms and check their action URLs
        forms = re.findall(r'<form\b[^>]*>(.*?)</form>', body, re.IGNORECASE | re.DOTALL)
        for form_html in forms:
            # Check if this form contains password or sensitive input
            if re.search(r'type=["\']password["\']', form_html, re.IGNORECASE):
                # Extract action attribute
                action_match = re.search(r'action=["\'](.*?)["\']', form_html, re.IGNORECASE)
                if action_match:
                    action_val = action_match.group(1).strip()
                    resolved_action = urljoin(response.url, action_val)
                    action_parsed = urlparse(resolved_action)
                    action_host = action_parsed.hostname or ""

                    # Form posting to external domain
                    if action_host and action_host.lower() != hostname.lower():
                        content_data["external_form_action"] = resolved_action
                        findings.append({
                            "id": "content_password_external_form",
                            "category": "HTML / DOM Content",
                            "title": "Credential Harvest: Form Posts to External Host",
                            "description": f"Password login form posts user credentials to foreign host '{action_host}' ({resolved_action}). Classic phishing exfiltration mechanism.",
                            "mitre": "T1056.003",
                            "severity": "CRITICAL"
                        })
                    
                    # Form posting over plain HTTP
                    if action_parsed.scheme.lower() == "http":
                        findings.append({
                            "id": "content_password_http_form",
                            "category": "HTML / DOM Content",
                            "title": "Credential Harvest: Form Posts to Unencrypted HTTP",
                            "description": f"Login credentials submitted over unencrypted cleartext HTTP endpoint: '{resolved_action}'.",
                            "mitre": "T1056.003",
                            "severity": "HIGH"
                        })

        # 3. Hidden iFrames
        hidden_iframe_pattern = r'<iframe\b[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|width=["\']0["\']|height=["\']0["\'])'
        if re.search(hidden_iframe_pattern, body, re.IGNORECASE):
            findings.append({
                "id": "content_hidden_iframe",
                "category": "HTML / DOM Content",
                "title": "Hidden iFrame Detected",
                "description": "Zero-dimension or hidden iframe detected. Used to overlay phishing frames, conduct clickjacking, or drop exploit kits.",
                "mitre": "T1027",
                "severity": "MEDIUM"
            })

        # 4. Anti-Analysis / Context Menu Disabling Scripts
        anti_analysis_pattern = r'(oncontextmenu\s*=\s*["\']return false|addEventListener\(["\']contextmenu["\']|keyCode\s*==\s*123)'
        if re.search(anti_analysis_pattern, body, re.IGNORECASE):
            findings.append({
                "id": "content_anti_analysis_script",
                "category": "HTML / DOM Content",
                "title": "Anti-Analysis / Right-Click Disabling Script",
                "description": "Page explicitly disables context menu, Developer Tools (F12), or source inspection to prevent defensive scrutiny.",
                "mitre": "T1027",
                "severity": "MEDIUM"
            })

        # 5. Missing Security Headers
        resp_headers = {k.lower(): v for k, v in response.headers.items()}
        for sec_hdr in ["content-security-policy", "x-frame-options", "strict-transport-security"]:
            if sec_hdr not in resp_headers:
                content_data["security_headers_missing"].append(sec_hdr)

    except requests.exceptions.RequestException as e:
        content_data["error"] = str(e)

    return {
        "data": content_data,
        "findings": findings
    }
