"""
SSL/TLS Certificate Security Analyzer.
Inspects cryptographic certificates, validity duration, self-signed origins, and issuer trust.
"""

import socket
import ssl
from datetime import datetime, timezone
from typing import Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from core.config import TARGETED_BRANDS


def get_certificate_details(hostname: str, port: int = 443) -> tuple[Optional[dict], Optional[str]]:
    """
    Establish TLS connection and retrieve DER/X509 certificate data.
    """
    clean_host = hostname.split(':')[0].strip('[]')
    try:
        # Create socket with short timeout
        sock = socket.create_connection((clean_host, port), timeout=4.0)
        context = ssl.create_default_context()
        # Avoid terminating prematurely on self-signed certs during inspection
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with context.wrap_socket(sock, server_hostname=clean_host) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)
            if not der_cert:
                return None, "No certificate returned by server"

            cert = x509.load_der_x509_certificate(der_cert, default_backend())
            
            # Extract Subject & Issuer
            subject = {attr.oid._name: attr.value for attr in cert.subject}
            issuer = {attr.oid._name: attr.value for attr in cert.issuer}

            # Extract Subject Alternative Names (SAN)
            sans = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                sans = san_ext.value.get_values_for_type(x509.DNSName)
            except Exception:
                pass

            details = {
                "subject_cn": subject.get("commonName", "Unknown"),
                "issuer_org": issuer.get("organizationName", issuer.get("commonName", "Unknown")),
                "not_before": cert.not_valid_before_utc,
                "not_after": cert.not_valid_after_utc,
                "sans": sans,
                "is_self_signed": cert.issuer == cert.subject
            }
            return details, None
    except Exception as e:
        return None, str(e)


def analyze_ssl(hostname: str, scheme: str, brand_target: Optional[str] = None) -> dict:
    """
    Analyze SSL/TLS configuration for cryptographic anomalies and trust indicators.
    """
    findings = []
    ssl_info = {
        "has_ssl": False,
        "issuer": "None",
        "subject_cn": "None",
        "days_remaining": None,
        "cert_age_days": None,
        "is_self_signed": False,
        "is_expired": False,
        "error": None
    }

    if scheme.lower() == "http":
        findings.append({
            "id": "ssl_missing_or_failed",
            "category": "SSL / Cryptography",
            "title": "Unencrypted HTTP Scheme",
            "description": "URL uses plain HTTP without SSL/TLS encryption. Sensitive data and credentials are sent in cleartext.",
            "mitre": "T1583.008",
            "severity": "HIGH"
        })
        return {"data": ssl_info, "findings": findings}

    # Attempt to retrieve certificate
    cert, err = get_certificate_details(hostname, port=443)
    if err or not cert:
        ssl_info["error"] = err or "Connection failed"
        findings.append({
            "id": "ssl_missing_or_failed",
            "category": "SSL / Cryptography",
            "title": "SSL/TLS Handshake Failure",
            "description": f"Failed to negotiate secure TLS session with {hostname}: {err}",
            "mitre": "T1583.008",
            "severity": "HIGH"
        })
        return {"data": ssl_info, "findings": findings}

    ssl_info["has_ssl"] = True
    ssl_info["issuer"] = cert["issuer_org"]
    ssl_info["subject_cn"] = cert["subject_cn"]
    ssl_info["is_self_signed"] = cert["is_self_signed"]

    now = datetime.now(timezone.utc)
    not_after = cert["not_after"]
    not_before = cert["not_before"]

    days_remaining = (not_after - now).days
    cert_age_days = (now - not_before).days
    ssl_info["days_remaining"] = days_remaining
    ssl_info["cert_age_days"] = max(0, cert_age_days)

    # 1. Self-Signed Certificate
    if cert["is_self_signed"]:
        findings.append({
            "id": "ssl_self_signed",
            "category": "SSL / Cryptography",
            "title": "Self-Signed Untrusted SSL Certificate",
            "description": "Certificate is self-signed and not issued by a trusted public Certificate Authority (CA). Common in phishing proxies (Evilginx2/Modlishka).",
            "mitre": "T1583.008",
            "severity": "CRITICAL"
        })

    # 2. Expired Certificate
    if now > not_after:
        ssl_info["is_expired"] = True
        findings.append({
            "id": "ssl_expired",
            "category": "SSL / Cryptography",
            "title": f"Expired SSL Certificate ({abs(days_remaining)} days ago)",
            "description": f"Certificate expired on {not_after.strftime('%Y-%m-%d')}.",
            "mitre": "T1583.008",
            "severity": "HIGH"
        })

    # 3. Freshly Issued Certificate (< 72 hours old)
    if cert_age_days <= 3:
        findings.append({
            "id": "ssl_short_validity",
            "category": "SSL / Cryptography",
            "title": f"Freshly Issued SSL Certificate ({cert_age_days} days ago)",
            "description": f"Certificate was provisioned on {not_before.strftime('%Y-%m-%d')} ({cert_age_days} days ago). Threat actors frequently generate certificates immediately prior to phishing deployment.",
            "mitre": "T1583.008",
            "severity": "MEDIUM"
        })

    # 4. Brand Mismatch in Certificate
    # If the URL claims to impersonate a brand (e.g. PayPal), but the certificate is issued to a generic or mismatched CN
    if brand_target:
        cn_lower = cert["subject_cn"].lower()
        sans_lower = [s.lower() for s in cert.get("sans", [])]
        brand_in_cert = brand_target in cn_lower or any(brand_target in s for s in sans_lower)
        
        # Check if the issuer is Let's Encrypt / cPanel auto-cert for a banking brand
        if "let's encrypt" in cert["issuer_org"].lower() or "cpanel" in cert["issuer_org"].lower():
            findings.append({
                "id": "ssl_brand_mismatch",
                "category": "SSL / Cryptography",
                "title": f"Automated Free DV Cert on Branded Domain ({cert['issuer_org']})",
                "description": f"Domain targets brand '{brand_target.upper()}' but uses automated Domain-Validated (DV) certificate from '{cert['issuer_org']}' rather than institutional enterprise CA.",
                "mitre": "T1583.008",
                "severity": "HIGH"
            })

    return {
        "data": ssl_info,
        "findings": findings
    }
