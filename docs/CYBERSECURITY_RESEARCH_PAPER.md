# Phishing Site Detection Technology: Academic Research & Technical Specification

## 1. Introduction & Threat Landscape
Phishing represents over 85% of initial organizational breaches according to the Verizon Data Breach Investigations Report (DBIR) and Anti-Phishing Working Group (APWG). Modern threat actors leverage automated infrastructure deployment kits, reverse-proxy frameworks (such as Evilginx2 and Modlishka) to bypass Multi-Factor Authentication (MFA), bulletproof hosting services, and dynamic DNS providers to stand up attack sites in minutes.

Traditional detection relying exclusively on static domain blocklists suffers from high latency: by the time a domain is reported and added to global feeds, the threat campaign has typically concluded. Consequently, proactive, client-side heuristic inspection engines are required to classify infrastructure at initial encounter.

---

## 2. Theoretical Framework & Vector Taxonomy

### 2.1 Lexical & URL Pattern Heuristics
Lexical analysis inspects the syntactic composition of the URL string prior to initiating any network connection.

* **IP Address in Hostname**:
  RFC 3986 defines host syntax. Attackers frequently bypass domain name registration requirements by hosting credential harvesters on direct IP addresses. Obfuscated variants include hexadecimal (`0x7f000001`), octal (`017700000001`), or integer DWORD representations.

* **IDN Homograph & Punycode Attacks**:
  Internationalized Domain Names (IDNs) facilitate non-ASCII characters across languages. Attackers exploit visually indistinguishable glyphs (homoglyphs) from Cyrillic or Greek alphabets (e.g. Cyrillic `а` U+0430 vs Latin `a` U+0061) to spoof established brands. Domains prefixed with `xn--` indicate Punycode encoding.

* **Shannon Entropy Analysis**:
  Domain Generation Algorithms (DGAs) dynamically create randomized domain names to evade perimeter defense. Shannon entropy mathematically models information density and unpredictability:
  
  $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
  
  Standard English brand domains typically range between $2.0 \le H(X) \le 3.4$. Entropy values exceeding $3.8$ correlate strongly with algorithmic generation or intentional payload obfuscation.

* **Combosquatting & Typosquatting**:
  Threat actors concatenate legitimate brand trademarks with sensitive action keywords (e.g., `paypal-security-check.com`, `microsoft-verify-auth.net`).

* **Authority Redirection Exploits (`@` Symbol)**:
  According to URL specification RFC 3986, characters preceding the `@` delimiter represent authentication credentials. Web browsers disregard credentials in modern navigation, silently routing the user to the destination host immediately following the `@`:
  `http://legitimate-service.com@malicious-harvesting-portal.com`

---

## 2.2 Network & DNS Infrastructure Telemetry

* **Domain Age (ICANN RDAP Telemetry)**:
  Registration Data Access Protocol (RDAP, RFC 7480) provides standardized JSON access to registry data. Statistical analysis demonstrates that >70% of phishing domains are registered less than 30 days prior to malicious deployment.

* **Mail Exchange (MX) & Authentication Records**:
  Authentic corporate domains operate mail infrastructures protected by MX, SPF (`v=spf1`), and DMARC (`v=DMARC1`) records. A domain imitating an enterprise or financial entity without configured MX routing exhibits strong anomalous behavior.

* **Fast-Flux DNS & TTL Dynamics**:
  Adversaries deploy Fast-Flux techniques, combining short DNS Time-To-Live (TTL < 60s) with round-robin A records pointing to rotating compromised botnet proxies.

---

## 2.3 Cryptographic & SSL/TLS Audit

* **The Misconception of HTTPS**:
  Widespread adoption of automated Domain-Validated (DV) Certificate Authorities (Let's Encrypt, ZeroSSL, Cloudflare) has democratized SSL. Consequently, over 80% of active phishing sites now serve traffic over valid HTTPS.
* **Certificate Anomalies**:
  - Freshly provisioned certificates issued $< 72$ hours prior.
  - Free automated DV certificates protecting domains purporting to belong to Tier-1 financial institutions (which customarily deploy Extended Validation / OV certificates).
  - Self-signed certificates or untrusted root authorities commonly present on man-in-the-middle reverse proxies.

---

## 2.4 Safe Passive HTML/DOM Inspection

When inspecting live content, executing active JavaScript poses severe operational security (OPSEC) risks (e.g. drive-by malware delivery). Safe passive inspection evaluates static DOM components without executing untrusted script code:
1. **Form Action Redirection**:
   Inspecting `<form action="...">` tags containing `<input type="password">`. If the action posts credentials to a different external host or an unencrypted HTTP endpoint, high-confidence credential theft is confirmed.
2. **Title-Domain Divergence**:
   Extracting `<title>` tags claiming brand affiliation while hosted on unverified third-party domains.
3. **Hidden Overlays & iFrames**:
   Identifying zero-pixel or hidden CSS iframes (`display:none`, `visibility:hidden`) utilized for clickjacking or silent credential capture.
4. **Anti-Analysis Controls**:
   Detecting script routines that intercept keyboard events (F12 Developer Tools block) or context menus (`oncontextmenu="return false"`).

---

## 3. Mathematical Scoring Engine

$$\text{Total Score } S = \min\left(100, \sum_{k} W_k \cdot \mathbb{I}(E_k)\right)$$

Where $W_k$ represents the empirical risk weight of indicator $E_k$, and $\mathbb{I}$ is the binary activation indicator.

### MITRE ATT&CK Correlation Table
| ATT&CK ID | Technique Name | Indicator Vector | Weight |
| :--- | :--- | :--- | :--- |
| `T1566.002` | Spearphishing Link | Brand spoofing + Credential keyword | +30 |
| `T1583.001` | Acquire Domains | High-abuse TLD / Newly registered domain | +30 |
| `T1583.008` | Malicious SSL Certs | Self-signed / Expired / Mismatched SSL | +30 |
| `T1584.004` | Compromise DNS | Fast-Flux DNS / Domain Resolution Failure | +25 |
| `T1056.003` | Web Portal Capture | Password form exfiltrating to external host | +40 |
| `T1027` | Obfuscated Code | Hidden iframe / Anti-analysis event blockers | +15 |
