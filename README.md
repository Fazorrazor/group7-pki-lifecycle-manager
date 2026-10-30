# Private PKI & Certificate Lifecycle Manager (Group 7)

**Course:** CSSS 441 Software Security I  
**Project:** Project 7 — Private PKI and Certificate Lifecycle Manager[cite: 7]  
**Group:** Group 7[cite: 15]

---

## 📖 Project Overview
This project implements a two-tier private Certificate Authority (CA) and an automated certificate lifecycle management platform for our lab network[cite: 7]. Every certificate lives for 30 days or less and renews automatically with zero downtime[cite: 7, 8]. Any wrong hostname, expired certificate, missing intermediate, or revoked certificate is automatically detected and reported within a single scan cycle[cite: 8].

---

## 👥 Team Roles & Module Allocation (Group 7)

### 1. Core Project 7 Deliverables Breakdown

| Member Name | Student ID | Role | Assigned Project 7 Modules |
| :--- | :--- | :--- | :--- |
| **Arnold Niikoi Djanie**[cite: 15] | `1692642491`[cite: 15] | **Team Lead & PKI Architect** | • **Module 1 (Two-Tier CA):** Offline Root CA and Online Intermediate CA setup, documented key ceremonies, name constraints, and path-length limits[cite: 7].<br>• **DevOps & Integration:** One-command Docker Compose setup, repository management, and Threat Model coordination[cite: 1]. |
| **Peter Myles Etroo**[cite: 15] | `1703154270`[cite: 15] | **ACME & Lab Infrastructure Lead** | • **Module 2 (ACME & Auto-Renewal):** `step-ca` ACME endpoint configuration and automated certificate issuance/renewal (≤30-day lifespan) for 5+ NGINX lab services via `certbot`/`lego` with zero downtime[cite: 7, 8]. |
| **Aaron Tettey-Fio**[cite: 15] | `1704456123`[cite: 15] | **Revocation & Crypto Engineer** | • **Module 3 (Revocation Infrastructure):** CRL and OCSP responder deployment[cite: 7].<br>• **Failure-Injection Testing:** Automated client tests proving revoked, expired, missing-intermediate, and wrong-hostname certificates are refused[cite: 7, 8]. |
| **Osei Elvis**[cite: 15] | `1703105081`[cite: 15] | **Backend & Inventory Service Lead** | • **Module 4 (TLS Inventory Service):** FastAPI backend and PostgreSQL database that connects to lab TLS endpoints and records issuer, expiry, key type/size, SANs, and chain completeness[cite: 8]. |
| **Daniel Odame Lartey**[cite: 15] | `1692180365`[cite: 15] | **Dashboard, Alerts & CT Lead** | • **Module 5 (Web Dashboard & Alerts):** Web UI displaying inventory health and triggering Email/Telegram alerts at 30, 7, and 1 days before expiry[cite: 8].<br>• **Module 6 (CT Monitoring):** Certificate Transparency monitoring via the `crt.sh` API for unexpected issuance alerts[cite: 8]. |
| **Edinam Afi Ezuh**[cite: 15] | `1700135424`[cite: 15] | **TLS Grading & Security QA Lead** | • **Module 7 (TLS Policy & Grading):** Automated `testssl.sh` scanner integration and policy engine flagging anything below TLS 1.2 with AEAD cipher suites[cite: 8].<br>• **Static Analysis & Verification:** Semgrep CI checks and before/after scan evidence collection[cite: 8, 11]. |

---

### 2. Week 2 Practical Allocation (`Input-Handling Kit`)

| Member Name | Assigned Week 2 Practical Task | Implementation Path | Status |
| :--- | :--- | :--- | :--- |
| **Arnold Niikoi Djanie**[cite: 15] | Repo initialization, project scaffolding, and CI | `docker-compose.yml`, `.github/workflows/ci.yml` | ✅ Completed |
| **Osei Elvis**[cite: 15] | **Task 1:** Pydantic request validation schemas (types, lengths, formats, ranges)[cite: 11] | `src/pki_lifecycle/validation/schemas.py` | ✅ Completed |
| **Peter Myles Etroo**[cite: 15] | **Task 2:** PostgreSQL data-access module using parameterized queries only[cite: 8, 11] | `src/pki_lifecycle/database/repository.py` | ✅ Completed |
| **Daniel Odame Lartey**[cite: 15] | **Task 3:** Auto-escaping template/UI rendering module for endpoint data[cite: 11] | `src/pki_lifecycle/rendering/templates.py` | ✅ Completed |
| **Aaron Tettey-Fio**[cite: 15] | **Task 4a:** 10 OWASP negative unit tests (quotes, SQLi payloads, malformed formats)[cite: 11] | `tests/test_validation_negative.py` (Tests 1-10) | ✅ Completed |
| **Edinam Afi Ezuh**[cite: 15] | **Task 4b & 5:** 10 OWASP negative unit tests (long strings, Unicode tricks, wrong types) & Semgrep remediation[cite: 11] | `tests/test_validation_negative.py` (Tests 11-20) | ✅ Completed |

---

## 📚 Project Documentation Hub

All formal deliverables, threat models, key ceremony logs, and technical reports are cataloged within the [`docs/`](docs/) directory:

* 🏛️ [**System Architecture & Cryptographic Specification**](docs/architecture.md) — Two-Tier CA design, X.509 constraints, and subsystem decomposition.
* 🛡️ [**Threat Model & STRIDE Matrix**](docs/threat-model/summary.md) — Level-1 DFD, 12 STRIDE threats, risk ratings, and chosen controls.
* 🗝️ [**Documented Key Ceremony & CA Hierarchy**](docs/key-ceremony/ceremony-notes.md) — Offline Root CA key ceremony protocols, custody sign-offs, and SHA-256 fingerprints.
* 🚀 [**Deployment & Operations Runbook**](docs/operations/deployment-guide.md) — One-command deployment, port mapping, and troubleshooting guide.
* 📡 [**REST API & OCSP/CRL Reference**](docs/operations/api-reference.md) — Complete endpoint documentation and request/response schemas.
* 🧪 [**Failure-Injection & Security Bar Verification**](docs/verification/failure-injection-tests.md) — Empirical evidence verifying detection of revoked, expired, and misconfigured certificates.
* 📊 [**TLS Configuration Policy & testssl.sh Evidence**](docs/verification/tls-grading-and-testssl.md) — Before-and-after audit reports and AEAD cipher enforcement.
* 🌐 [**Certificate Transparency Monitoring**](docs/verification/certificate-transparency.md) — Rogue CA detection via `crt.sh` API.
* 📑 [**Academic Final Report (10–15 Pages)**](docs/report/project-report.md) — Comprehensive final submission covering design, verification, and member contributions.

---

## 🛠️ Tech Stack & Lab Environment
* **PKI & ACME Server:** `step-ca`, OpenSSL, `certbot` / `lego`[cite: 8]
* **Lab Web Servers:** NGINX (5+ containerized internal endpoints)[cite: 7, 8]
* **Backend & Database:** Python (FastAPI), Pydantic, PostgreSQL[cite: 8, 11]
* **Security & Verification:** `testssl.sh`, `crt.sh` API, Semgrep, Pytest[cite: 8, 11]
* **Orchestration:** Docker Compose[cite: 1]

---

## 🚀 Quick Start (One-Command Setup)

```bash
# 1. Clone the repository
git clone <repo-url>
cd group7-private-pki

# 2. Run the Week 2 Input-Handling Kit unit tests & Semgrep check
pytest tests/
semgrep scan --config auto .

# 3. Launch the full PKI lab environment and dashboard (Docker Compose)
docker compose up --build -d