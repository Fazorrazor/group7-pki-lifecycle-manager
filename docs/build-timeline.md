# Project Build Timeline & Milestone Tracker

**Course:** CSSS 441 Software Security I  
**Project:** Project 7 — Private PKI and Certificate Lifecycle Manager  
**Group:** Group 7  
**Academic Year:** Level 400, Semester 1  

This document serves as the master engineering progress tracker for Project 7. Completed items are marked `[x]`, while in-progress and remaining deliverables are left unmarked `[ ]`.

---

## 📊 Overall Progress Summary

```
[████████████████████████] 95% Completed
Core Crypto & Backend:    100% [x]
Tests & Security Bar:     100% [x]
Documentation Suite:      100% [x]
Live Container Fleet:     100% [x]
Automated Scripts:        100% [x]
Final Week 10 Media:       50% [ ]
```

---

## 🛠️ Phase-by-Phase Build Tracker

### Phase 1: Repository Scaffolding, Threat Modeling & Input-Handling Kit (Weeks 1–2)
- [x] **Repository Scaffolding:** Project structure established (`src/pki_lifecycle`, `tests`, `docs`, `templates`, `docker`, `scripts`).
- [x] **Week 1 Threat Modeling:** Level-1 Data Flow Diagram (DFD) and 12-threat STRIDE analysis documented ([`docs/threat-model/summary.md`](docs/threat-model/summary.md)).
- [x] **Threat Dragon Export:** OWASP Threat Dragon JSON exported ([`docs/threat-model/threat-model.json`](docs/threat-model/threat-model.json)).
- [x] **Week 2 Input-Handling Kit:**
  - [x] Strict Pydantic request validation schemas (`types, lengths, formats, ranges`) in [`src/pki_lifecycle/validation/schemas.py`](src/pki_lifecycle/validation/schemas.py).
  - [x] Parameterized SQL data access module in [`src/pki_lifecycle/database/repository.py`](src/pki_lifecycle/database/repository.py).
  - [x] Auto-escaping template rendering engine in [`src/pki_lifecycle/rendering/templates.py`](src/pki_lifecycle/rendering/templates.py).
  - [x] 20 negative OWASP unit tests passing in [`tests/test_validation_negative.py`](tests/test_validation_negative.py).
  - [x] Clean Semgrep SAST scan with zero findings.

---

### Phase 2: Cryptographic Engine & Two-Tier CA Architecture (Module 1)
- [x] **Offline Root CA Implementation:**
  - [x] 4096-bit RSA private key generation with SHA-256 in [`src/pki_lifecycle/crypto/authority.py`](src/pki_lifecycle/crypto/authority.py).
  - [x] Enforce `basicConstraints = critical, CA:TRUE, pathlen:1`.
  - [x] Enforce `keyUsage = critical, keyCertSign, cRLSign`.
- [x] **Online Intermediate CA Implementation:**
  - [x] 2048-bit RSA key signed by Root CA.
  - [x] Enforce `basicConstraints = critical, CA:TRUE, pathlen:0` (strictly prevents subordinate CA creation).
  - [x] Enforce `nameConstraints = critical, permitted;DNS:.internal.lab` (prevents external domain forgery).
- [x] **Documented Key Ceremonies:**
  - [x] Comprehensive Key Ceremony protocol and custody log documented in [`docs/key-ceremony/ceremony-notes.md`](docs/key-ceremony/ceremony-notes.md).
- [x] **Standalone CA Bootstrap Script:**
  - [x] CLI ceremony generator in [`scripts/init_ca_ceremony.py`](scripts/init_ca_ceremony.py) exporting PEM certificates and keys to `docker/certs/ca/`.

---

### Phase 3: Revocation Infrastructure — CRL & OCSP (Module 3)
- [x] **RFC 5280 CRL Generator:** Signed CRL generation implemented at `GET /api/v1/crl`.
- [x] **RFC 6960 OCSP Responder Engine:**
  - [x] In-memory revocation cache and state machine (`good`, `revoked`, `unknown`) in [`src/pki_lifecycle/crypto/ocsp_responder.py`](src/pki_lifecycle/crypto/ocsp_responder.py).
  - [x] Lightweight JSON OCSP endpoint at `GET /api/v1/ocsp/{serial_number}`.
  - [x] Binary DER OCSP endpoint at `POST /api/v1/ocsp`.
  - [x] Nonce verification and replay protection with short validity window ($\le 1\text{ hr}$).
- [x] **Failure-Injection Test Case:** Automated test proving revoked certificate refusal in [`tests/test_failure_injection.py`](tests/test_failure_injection.py) (`test_01_client_refuses_revoked_certificate_via_ocsp`).
- [x] **Live OCSP Verification Script:**
  - [x] Interactive verification scripts in [`scripts/test_ocsp_live.sh`](scripts/test_ocsp_live.sh) and [`scripts/test_ocsp_live.ps1`](scripts/test_ocsp_live.ps1) for terminal demonstrations.

---

### Phase 4: ACME Automated Issuance & Zero-Downtime Renewal (Module 2)
- [x] **30-Day Lifespan Policy Enforcement:**
  - [x] Hard cap rejecting any issuance request $>30$ days with HTTP 400.
  - [x] Verified via `test_05_max_30_day_lifespan_enforcement`.
- [x] **Zero-Downtime Renewal Manager:**
  - [x] `ACMERenewalManager` tracking the 5 lab services (`auth`, `billing`, `vault`, `metrics`, `portal`) in [`src/pki_lifecycle/acme/renewal.py`](src/pki_lifecycle/acme/renewal.py).
  - [x] Automatic on-disk PEM synchronization (`_export_to_disk`) directly populating `docker/certs/`.
  - [x] Renewal trigger logic evaluating threshold ($\le 7\text{ days}$).
  - [x] Atomic key rotation simulation recording `downtime_seconds = 0.0`.

---

### Phase 5: TLS Inventory Service & Active Scanner (Module 4)
- [x] **Live Network Prober:**
  - [x] Sockets-based TLS handshake prober in [`src/pki_lifecycle/inventory/collector.py`](src/pki_lifecycle/inventory/collector.py).
  - [x] Full X.509 chain parser extracting Serial, CN, SANs, Issuer, Expiry, Key Size, and Cipher.
- [x] **Single-Scan-Cycle Security Bar Detection:**
  - [x] Detection of expired certificates (`test_02_scanner_detects_expired_certificate`).
  - [x] Detection of wrong hostname / SAN mismatch (`test_03_scanner_detects_wrong_hostname`).
  - [x] Detection of missing intermediate certificates (`test_04_scanner_detects_missing_intermediate_chain`).
  - [x] Detection of revoked certificates within 1 cycle (`test_01_client_refuses_revoked_certificate_via_ocsp`).
- [x] **Fleet Orchestrator & Background Worker:**
  - [x] Continuous background worker loop in [`src/pki_lifecycle/main.py`](src/pki_lifecycle/main.py) executing scans every 30 seconds and triggering automated renewals.

---

### Phase 6: TLS Configuration Grading & testssl.sh (Module 7)
- [x] **TLS Policy Engine:**
  - [x] Protocol and cipher suite evaluation in [`src/pki_lifecycle/grading/policy.py`](src/pki_lifecycle/grading/policy.py).
  - [x] Strict grading: Grade A+ (TLS 1.3 AEAD), Grade A (TLS 1.2 AEAD), Grade B (TLS 1.2 CBC), Grade F ($< \text{TLS } 1.2$).
  - [x] Verified via unit tests in [`tests/test_grading.py`](tests/test_grading.py).
- [x] **Before/After Remediation Documentation:**
  - [x] Full testssl.sh audit evidence recorded in [`docs/verification/tls-grading-and-testssl.md`](docs/verification/tls-grading-and-testssl.md).
- [x] **Automated `testssl.sh` Runner Scripts:**
  - [x] Runner scripts in [`scripts/run_testssl.sh`](scripts/run_testssl.sh) and [`scripts/run_testssl.ps1`](scripts/run_testssl.ps1) targeting ports 8443–8447.

---

### Phase 7: Certificate Transparency (CT) Monitoring (Module 6)
- [x] **`crt.sh` Polling Engine:**
  - [x] Public log querying logic in [`src/pki_lifecycle/ct_monitor/monitor.py`](src/pki_lifecycle/ct_monitor/monitor.py).
  - [x] Whitelist evaluation against authorized CAs (`Group 7 Intermediate`, `Group 7 Root`, `Let's Encrypt`).
- [x] **Rogue CA Anomaly Trigger:**
  - [x] Automatic dispatch of `CRITICAL` alert upon discovering unauthorized issuers.
  - [x] Simulation endpoint `POST /api/v1/ct-monitor/simulate-rogue`.
  - [x] Verified via `test_07_ct_monitoring_flags_unauthorized_issuer`.
- [x] **Periodic Scheduled Auditing:**
  - [x] Ingested every ~5 minutes by background lifecycle worker in `main.py`.

---

### Phase 8: Web Dashboard & Multi-Channel Alerts (Module 5)
- [x] **Interactive Web UI:**
  - [x] Jinja2 template [`templates/dashboard.html`](templates/dashboard.html) displaying live KPIs, Endpoint Table, Certificate Cards, and Renewal Logs.
  - [x] Contextual auto-escaping preventing stored XSS (`tests/test_rendering.py`).
- [x] **Multi-Threshold Expiry Logic:**
  - [x] Evaluates certificates at 30-day (`INFO`), 7-day (`WARNING`), and 1-day (`CRITICAL`) thresholds.
  - [x] Verified via `test_06_expiry_alert_thresholds`.
- [x] **Live Telegram Webhook Dispatcher:**
  - [x] Outbound `httpx.post` integration in [`src/pki_lifecycle/alerts/dispatcher.py`](src/pki_lifecycle/alerts/dispatcher.py) delivering notifications to Telegram chat.

---

### Phase 9: Lab Infrastructure & Docker Orchestration
- [x] **PostgreSQL Container (`pki-postgres`):** Configured with healthchecks, persistent volumes, and initialization script [`docker/postgres/init.sql`](docker/postgres/init.sql).
- [x] **FastAPI Backend Container (`pki-backend`):** Hardened non-root user image with healthchecks and certificate mount.
- [x] **step-ca ACME Container (`pki-step-ca`):** Smallstep image on port 9000.
- [x] **Hardened NGINX Lab Endpoints:**
  - [x] Created `docker/nginx/` configs (`auth.conf`, `billing.conf`, `vault.conf`, `metrics.conf`, `portal.conf`) enforcing TLS 1.2/1.3 and AEAD ciphers.
  - [x] Mounted SSL certificates (`docker/certs/`) and configurations into containers (`8443–8447`).

---

### Phase 10: Final Academic Deliverables (Week 10)
- [x] **System Architecture Document:** [`docs/architecture.md`](docs/architecture.md).
- [x] **Threat Model & STRIDE Table:** [`docs/threat-model/summary.md`](docs/threat-model/summary.md).
- [x] **Key Ceremony Notes:** [`docs/key-ceremony/ceremony-notes.md`](docs/key-ceremony/ceremony-notes.md).
- [x] **Deployment Guide:** [`docs/operations/deployment-guide.md`](docs/operations/deployment-guide.md).
- [x] **API Reference:** [`docs/operations/api-reference.md`](docs/operations/api-reference.md).
- [x] **Academic Final Report (Draft):** [`docs/report/project-report.md`](docs/report/project-report.md).
- [ ] **Two Weeks of Continuous Renewal Logs:** Collect extended production rotation logs over time.
- [ ] **5-Minute Demo Video:** Screen recording demonstrating clean Docker startup, dashboard KPIs, live revocation rejection, and zero-downtime rotation.
- [ ] **15-Minute Live Presentation Slides:** Presentation deck covering threat model, cryptographic engineering, verification results, and team contributions.
