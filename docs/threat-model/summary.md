# Threat Model Summary: Private PKI & Certificate Lifecycle Manager

**Course:** CSSS 441 Software Security I  
**Project:** Project 7 — Private PKI and Certificate Lifecycle Manager  
**Group:** Group 7 (Lead: Arnold Niikoi Djanie)  
**Deliverable:** Week 1 Practical Submission  

---

## 1. System Overview & Level-1 Data Flow Diagram (DFD)

The system manages end-to-end certificate issuance, renewal, revocation, and compliance monitoring across internal lab services. It operates across four distinct trust boundaries:
1. **Air-Gapped Offline Root CA Boundary:** Completely isolated environment where the Root CA private key resides and only signs the Intermediate CA.
2. **Internal Management Zone:** Houses the `step-ca` ACME server, the FastAPI inventory/backend service, and PostgreSQL database.
3. **Lab Services DMZ:** Hosts 5+ NGINX containerized endpoints communicating over TLS with automated `certbot`/`lego` renewal.
4. **External/Internet Boundary:** Outbound connection to Certificate Transparency (CT) logs (`crt.sh` API) and notification channels (Telegram/SMTP).

```
[Air-Gapped Root CA] 
         │ (Offline Signed Cert)
         ▼
[step-ca Intermediate CA] <───(ACME Protocol)───> [NGINX Lab Endpoints (x5)]
         │                                                    │
         ▼ (Status & Events)                                  ▼ (TLS Scans)
[FastAPI Inventory Engine] <───────────────────────── [testssl.sh Scanner]
         │
    ┌────┴──────────────────────────┐
    ▼                               ▼
[PostgreSQL DB]          [Web Dashboard & Alerts] ───> [CT Monitor (crt.sh)]
```

---

## 2. STRIDE Threat Catalog & Risk Ratings (12 Threats)

Ratings are calculated using the Course Risk Matrix: **Risk = Likelihood × Impact** (High / Medium / Low).

| # | Threat Name | STRIDE Category | Target Element | Likelihood | Impact | Risk Rating | Rating Rationale |
|---|:---|:---|:---|:---:|:---:|:---:|:---|
| **T1** | Intermediate CA Key Exfiltration | Information Disclosure | `step-ca` Intermediate CA | Low | Critical | **High** | Compromise allows adversary to forge valid certificates for any domain. |
| **T2** | ACME Domain Impersonation | Spoofing | ACME Endpoint / Client | Medium | High | **High** | Attacker claims unauthorized internal domain names without domain control verification. |
| **T3** | SQL Injection via Endpoint Search | Tampering | FastAPI / DB Layer | Medium | High | **High** | Untrusted input in query parameters could alter DB schema or dump credentials. |
| **T4** | Stored XSS via Malicious Cert SANs | Tampering | Dashboard UI | Medium | High | **High** | Attackers injecting script tags into SAN extensions execute in admin browser context. |
| **T5** | Stale OCSP Response Replay | Tampering | OCSP Responder | Medium | High | **High** | Replaying signed "Good" OCSP tokens allows revoked certificates to be accepted. |
| **T6** | OCSP Responder Denial of Service | Denial of Service | OCSP Service | High | Medium | **High** | Service outage triggers soft-fail client policies, bypassing revocation checks. |
| **T7** | CA Path Length & Constraint Bypass | Elevation of Privilege | Issued Certificates | Low | Critical | **High** | Without `pathlen:0` and Name Constraints, end-entity certs can act as rogue CAs. |
| **T8** | Weak Cipher Suite Downgrade | Information Disclosure | NGINX Endpoints | Medium | Medium | **Medium** | Supporting TLS 1.0/1.1 or CBC suites exposes traffic to BEAST/POODLE attacks. |
| **T9** | Missing Intermediate Chain DoS | Denial of Service | NGINX TLS Handshake | High | Low | **Medium** | Server serving only leaf cert without intermediate causes strict clients to abort. |
| **T10** | Direct Database Audit Tampering | Repudiation | PostgreSQL Store | Low | High | **Medium** | Unaudited manual updates could wipe evidence of compromised certificate issuance. |
| **T11** | Inventory Scan Flooding | Denial of Service | Inventory API | High | Low | **Medium** | Malicious burst of scan triggers exhausts worker threads and memory. |
| **T12** | Alert Notification Spoofing / Drop | Tampering | Alert Dispatcher | Low | Medium | **Low** | Man-in-the-middle dropping Telegram/SMTP alerts hides impending expirations. |

---

## 3. Top 5 Threats & Chosen Security Controls

1. **Threat T1 (Intermediate Key Exfiltration) & T7 (Constraint Bypass):**
   * **Controls:** 
     - Root CA stored offline and powered down.
     - Intermediate CA certificates enforce strict X.509 extensions: `basicConstraints = CA:TRUE, pathlen:0` and `nameConstraints = permitted;DNS:.internal.lab`.
     - File system permissions locked (`chmod 0400`) on private key directories.
2. **Threat T2 (ACME Domain Impersonation):**
   * **Controls:**
     - ACME provisioner configured with strict validation (DNS-01 or internal HTTP-01 challenge restricted to internal IP ranges).
     - Automated issuance capped at **≤30 days lifespan**.
3. **Threat T3 (SQL Injection):**
   * **Controls:**
     - Strict Pydantic input schemas (types, formats, max-length limits).
     - 100% parameterized queries in the database repository (zero string formatting / concatenation).
4. **Threat T4 (Stored Cross-Site Scripting):**
   * **Controls:**
     - Contextual auto-escaping enabled on all UI and dashboard templates (`autoescape=True` with Jinja2 / `html.escape`).
     - Content-Security-Policy (CSP) headers disallowing inline script execution.
5. **Threat T5 & T6 (Revocation Bypasses):**
   * **Controls:** 
     - Nonce enforcement in OCSP requests/responses with short validity windows (≤ 1 hour).
     - Automated failure-injection tests in CI proving clients hard-fail when certificates are revoked.

---

## 4. Verification: Boundary-Crossing Data Flows & Recorded Threats

As mandated by the Week 1 Practical specification (*"Done when every data flow that crosses a boundary has at least one threat recorded against it"*), every boundary-crossing data flow is explicitly evaluated with a STRIDE threat:

| Data Flow ID & Name | Boundary Crossed | STRIDE Category | Specific Threat Recorded | Mitigation Control |
|:---|:---|:---:|:---|:---|
| **Flow 1:** Offline Sub-CA Signing | Air-Gapped Root CA $\rightarrow$ Management Zone | **Tampering** | Malicious USB Drop / Intermediate CSR Tampering | Cryptographic SHA-256 fingerprint validation, dual-custody key ceremony protocol, and air-gapped signing. |
| **Flow 2:** ACME Auto-Issuance & Renew | Lab Services DMZ $\rightarrow$ Management Zone | **Spoofing** | ACME Challenge Hijacking / Unauthorized SAN Request | Internal HTTP-01/DNS-01 challenge restricted to internal IP ranges and CA Name Constraints (`.internal.lab`). |
| **Flow 3:** OCSP Revocation Check | Lab Services DMZ $\rightarrow$ Management Zone | **Tampering** | OCSP Response Replay or Stripping Attack | RFC 6960 OCSP nonces enforced, short cache windows (≤ 1h), and hard-fail client revocation policy. |
| **Flow 4:** TLS Inventory Probing | Management Zone $\rightarrow$ Lab Services DMZ | **Information Disclosure** | Man-in-the-Middle Probe Interception / Cert Forgery | Strict X.509 root-anchored trust chain validation and client certificate authentication during scans. |
| **Flow 7:** Poll CT Logs (`crt.sh`) | Management Zone $\rightarrow$ External Public Internet | **Tampering** | CT Log Query Suppression / Poisoning Evasion | TLS certificate pinning for `crt.sh`, multi-source log querying, and automated alerts on query failures. |
