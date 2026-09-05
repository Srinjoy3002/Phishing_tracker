"""
Passive HTML and DOM Security Inspector with OPSEC Proxy Routing.
Safely extracts credential forms, PyPhisher/Zphisher kit signatures,
victim IP-logging scripts, and brand divergence.
Routes through Tor or custom SOCKS/HTTP proxies to protect analyst identity.
"""

import re
from urllib.parse import urljoin, urlparse
from typing import Optional
import requests
from core.config import (
    STEALTH_HEADERS,
    REQUEST_TIMEOUT,
    TARGETED_BRANDS,
    PHISHING_KIT_ENDPOINTS,
    EXFILTRATION_PATTERNS
)


def analyze_content(
    target_url: str,
    hostname: str,
    brand_target: Optional[str] = None,
    is_reverse_tunnel: bool = False,
    proxies: Optional[dict] = None
) -> dict:
    """
    Perform safe, non-executing passive content inspection on the target URL.
    Supports Tor/Proxy tunneling to prevent analyst IP and geolocation leakage.
    """
    findings = []
    content_data = {
        "status_code": None,
        "title": "None",
        "redirect_history": [],
        "has_password_field": False,
        "external_form_action": None,
        "phishing_kit_endpoints_found": [],
        "exfiltration_channels": [],
        "victim_trackers": [],
        "security_headers_missing": [],
        "inspected": False,
        "error": None,
        "routed_via_proxy": bool(proxies)
    }

    # Use realistic stealth browser headers
    headers = dict(STEALTH_HEADERS)

    # Disable SSL warnings for inspection of untrusted certs
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    try:
        response = requests.get(
            target_url,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            verify=False,
            proxies=proxies
        )
        content_data["inspected"] = True
        content_data["status_code"] = response.status_code

        if response.history:
            content_data["redirect_history"] = [r.url for r in response.history]

        body = response.text[:600000]

        # 1. Page Title & Meta Brand Impersonation
        title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        page_title = title_match.group(1).strip() if title_match else ""
        content_data["title"] = page_title[:100] if page_title else "None"

        # Search meta tags and og:title
        meta_tags = re.findall(r'<meta\s+[^>]*content=["\'](.*?)["\']', body, re.IGNORECASE)
        combined_dom_text = (page_title + " " + " ".join(meta_tags)).lower()

        detected_brand = brand_target
        for brand, legit_domains in TARGETED_BRANDS.items():
            if brand in combined_dom_text:
                is_official = any(hostname == dom or hostname.endswith("." + dom) for dom in legit_domains)
                if not is_official:
                    detected_brand = brand
                    findings.append({
                        "id": "content_title_brand_mismatch",
                        "category": "Phishing Signature",
                        "title": f"Brand Cloned Portal: {brand.upper()}",
                        "description": f"Page claims to be '{brand.upper()}' in DOM metadata/title ('{page_title}'), but is hosted on unauthorized domain '{hostname}'. Signature of cloned login templates.",
                        "mitre": "T1566.002",
                        "severity": "CRITICAL"
                    })
                    break

        # 2. Form & Credential Harvesting Analysis
        has_password = bool(re.search(r'<input[^>]+type=["\']password["\']', body, re.IGNORECASE))
        content_data["has_password_field"] = has_password

        # Compound Signature: Reverse Tunnel Hosting a Login Page (PyPhisher / Zphisher)
        if is_reverse_tunnel and has_password:
            findings.append({
                "id": "reverse_tunnel_with_login",
                "category": "Phishing Signature",
                "title": "Credential Harvester on Reverse Tunnel (PyPhisher/Zphisher)",
                "description": f"Target hosts a credential authentication/password form directly on an ephemeral reverse-tunnel service ({hostname}). Zero legitimate enterprise services operate production login portals on free tunnel infrastructure.",
                "mitre": "T1056.003",
                "severity": "CRITICAL"
            })

        # Scan Form Action URLs and Inputs
        # Group 1 = form opening tag attributes, Group 2 = inner form body
        forms = re.findall(r'<form\b([^>]*)>(.*?)</form>', body, re.IGNORECASE | re.DOTALL)
        for form_attrs, form_body in forms:
            full_form = form_attrs + " " + form_body
            action_match = re.search(r'action=["\'](.*?)["\']', form_attrs, re.IGNORECASE)
            action_val = action_match.group(1).strip() if action_match else ""
            action_clean = action_val.split('?')[0].lower()

            # Check for known phishing kit submission endpoints (login.php, post.php, etc.)
            for kit_ep in PHISHING_KIT_ENDPOINTS:
                if action_clean == kit_ep or action_clean.endswith("/" + kit_ep):
                    content_data["phishing_kit_endpoints_found"].append(action_val)
                    findings.append({
                        "id": "phishing_kit_endpoint",
                        "category": "Phishing Kit Artifact",
                        "title": f"Phishing Kit Backend Endpoint ('{action_val}')",
                        "description": f"Form action targets '{action_val}', a standard credential harvesting script used by automated frameworks (PyPhisher, Zphisher, Maskphish).",
                        "mitre": "T1056.003",
                        "severity": "CRITICAL"
                    })
                    break

            # Check if this form contains password
            if re.search(r'type=["\']password["\']', full_form, re.IGNORECASE) and action_val:
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

        # 3. Phishing Kit Exfiltration Channels & Victim Trackers
        for pat_name, (pattern, pat_desc) in EXFILTRATION_PATTERNS.items():
            if re.search(pattern, body, re.IGNORECASE):
                if pat_name in ["telegram_bot", "discord_webhook"]:
                    content_data["exfiltration_channels"].append(pat_name)
                    findings.append({
                        "id": "credential_exfiltration_channel",
                        "category": "Phishing Kit Artifact",
                        "title": pat_desc,
                        "description": f"Embedded script contains active exfiltration channel ({pat_name}) used to forward victim credentials directly to attacker channels.",
                        "mitre": "T1056.003",
                        "severity": "CRITICAL"
                    })
                elif pat_name == "ip_logger_api":
                    content_data["victim_trackers"].append("IP/Geo Logger")
                    findings.append({
                        "id": "victim_tracking_script",
                        "category": "OPSEC Alert / Kit Tracker",
                        "title": "Victim IP/Geolocation Logger Detected (PyPhisher Footprint)",
                        "description": "Page executes client-side IP or geolocation lookup (ip-api.com / ipify / ipinfo). This confirms the phishing kit attempts to record the visitor's IP and physical location.",
                        "mitre": "T1027",
                        "severity": "HIGH"
                    })
                elif pat_name == "geolocation_api":
                    findings.append({
                        "id": "geolocation_harvesting",
                        "category": "Phishing Kit Artifact",
                        "title": "HTML5 Geolocation Permission Prompt",
                        "description": "Page requests high-accuracy GPS coordinates via navigator.geolocation to harvest victim coordinates.",
                        "mitre": "T1027",
                        "severity": "HIGH"
                    })
                elif pat_name == "camphish_webrtc":
                    findings.append({
                        "id": "webcam_harvesting_script",
                        "category": "Phishing Kit Artifact",
                        "title": "Webcam / Media Device Capture Hook (CamPhish Signature)",
                        "description": "Page requests getUserMedia camera/mic access to capture victim imagery.",
                        "mitre": "T1027",
                        "severity": "CRITICAL"
                    })

        # 4. Hidden iFrames
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

        # 5. Anti-Analysis Scripts
        anti_analysis_pattern = r'(oncontextmenu\s*=\s*["\']return false|addEventListener\(["\']contextmenu["\']|keyCode\s*==\s*123)'
        if re.search(anti_analysis_pattern, body, re.IGNORECASE):
            findings.append({
                "id": "content_anti_analysis_script",
                "category": "HTML / DOM Content",
                "title": "Anti-Analysis / Right-Click Disabling Script",
                "description": "Page explicitly disables context menu or Developer Tools (F12) to prevent defensive inspection.",
                "mitre": "T1027",
                "severity": "MEDIUM"
            })

        # 6. Missing Security Headers
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
