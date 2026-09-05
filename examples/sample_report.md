# PhishTracker Triage Report: 192.168.1.100
**Generated:** 2026-09-05 08:14:16 UTC  
**Target URL:** `http://192.168.1.100/secure-banking/login.php`  
**Risk Score:** `45 / 100` (LOW RISK)  

---

## Executive Summary
- **Threat Classification:** LOW RISK
- **Calculated Risk Score:** 45 / 100
- **Indicators Flagged:** 2

---

## Technical Telemetry
| Vector | Observed Telemetry |
| :--- | :--- |
| Domain | `192.168.1.100` |
| Scheme | `http` |
| Resolved IPs | `None` |
| Domain Age | `Unknown days` |
| Registrar | `Unknown` |
| SSL Issuer | `None` |
| Domain Entropy | `0.0` |
| HTML Title | `None` |

---

## Flagged Indicators & Evidence
| Severity | Category | Indicator | MITRE ATT&CK | Description |
| :--- | :--- | :--- | :--- | :--- |
| **HIGH** | Lexical | IP Address Used in Hostname | `T1566.002` | URL uses raw IP '192.168.1.100' instead of a legitimate domain name to evade domain registration scrutiny. |
| **MEDIUM** | Lexical | Credential / Lure Keywords Detected (login, secure, banking) | `T1566.002` | URL contains multiple high-risk credential harvesting keywords: login, secure, banking |

---

## Recommended Actions
- ✅ No critical phishing signatures identified. Standard perimeter monitoring applies.