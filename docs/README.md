# Project Documentation Portal (Group 7)

**Course:** CSSS 441 Software Security I  
**Project:** Project 7 — Private PKI and Certificate Lifecycle Manager  
**Group:** Group 7  
**Academic Year:** Level 400, Semester 1  

Welcome to the comprehensive documentation suite for the **Private PKI & Certificate Lifecycle Manager**. This directory contains all technical designs, operational runbooks, security verifications, threat models, and academic deliverables required by the course syllabus.

---

## 🗂️ Documentation Directory Structure

```
docs/
├── README.md                           # Documentation Index & Navigation Portal (This File)
├── architecture.md                     # Comprehensive System Architecture & Cryptographic Blueprint
├── build-timeline.md                   # Engineering Build Timeline & Milestone Tracker
│
├── threat-model/                       # Week 1 & 4 Milestone Deliverables
│   ├── summary.md                      # STRIDE per-element analysis, Level-1 DFD, Risk Ratings & Controls
│   └── threat-model.json               # OWASP Threat Dragon export
│
├── key-ceremony/                       # Module 1 Deliverable (Evidence to Submit)
│   └── ceremony-notes.md               # CA Hierarchy, Offline Root Key Ceremony Protocol, Custody Logs & Name Constraints
│
├── operations/                         # Deployment & Integration Documentation (10 Marks Criteria)
│   ├── deployment-guide.md             # One-Command Quickstart, Prerequisites, Docker Compose & Production Runbook
│   └── api-reference.md                # Full REST API, OCSP/CRL endpoints, ACME mechanics & JSON Schemas
│
├── verification/                       # Security Bar Verification & Evidence Reports
│   ├── failure-injection-tests.md      # Security Bar Testing: Revocation, Expiry, Wrong SAN, Incomplete Chain
│   ├── tls-grading-and-testssl.md      # TLS Policy Engine, AEAD validation & testssl.sh before/after evidence
│   └── certificate-transparency.md     # crt.sh API Ingestion, Rogue CA Detection & Alerting Workflows
│
└── report/                             # Week 10 Academic Final Report
    └── project-report.md               # 10-15 Page Project Report: Design, Controls, Verification, Residual Risk
```

---

## 📚 Deliverables & Course Milestone Mapping

| Course Milestone | Required Deliverable | Primary Document Link | Lead Member |
| :--- | :--- | :--- | :--- |
| **Week 1 & 2** | Topic Confirmation, Team Allocation & Input-Handling Kit | [`README.md (Root)`](file:///c:/Users/PC/OneDrive/Documents/DOCS/UNI%20files/LVL%20400/1st%20semester/CSSS%20441%20Software%20Security/projects/KPI%20and%20certificate%20lifecycle%20manager/README.md) | Arnold Niikoi Djanie |
| **Week 4 (5%)** | Threat Model (DFD, STRIDE table, Chosen Controls) | [`docs/threat-model/summary.md`](file:///c:/Users/PC/OneDrive/Documents/DOCS/UNI%20files/LVL%20400/1st%20semester/CSSS%20441%20Software%20Security/projects/KPI%20and%20certificate%20lifecycle%20manager/docs/threat-model/summary.md) | Arnold Niikoi Djanie |
| **Week 4 (5%)** | Architecture Diagram & Cryptographic Specification | [`docs/architecture.md`](file:///c:/Users/PC/OneDrive/Documents/DOCS/UNI%20files/LVL%20400/1st%20semester/CSSS%20441%20Software%20Security/projects/KPI%20and%20certificate%20lifecycle%20manager/docs/architecture.md) | Arnold Niikoi Djanie |
| **Week 6 & 7** | Working Core Demo (ACME Issuance, OCSP Revocation, Dashboard) | [`docs/operations/deployment-guide.md`](file:///c:/Users/PC/OneDrive/Documents/DOCS/UNI%20files/LVL%20400/1st%20semester/CSSS%20441%20Software%20Security/projects/KPI%20and%20certificate%20lifecycle%20manager/docs/operations/deployment-guide.md) | Peter Myles Etroo |
| **Week 9** | Failure Injection Suite & TLS Configuration Grading | [`docs/verification/failure-injection-tests.md`](file:///c:/Users/PC/OneDrive/Documents/DOCS/UNI%20files/LVL%20400/1st%20semester/CSSS%20441%20Software%20Security/projects/KPI%20and%20certificate%20lifecycle%20manager/docs/verification/failure-injection-tests.md) | Aaron Tettey-Fio & Edinam Afi Ezuh |
| **Week 10 (25%)** | Final 10–15 Page Report, Audit Evidence & Demo Defense | [`docs/report/project-report.md`](file:///c:/Users/PC/OneDrive/Documents/DOCS/UNI%20files/LVL%20400/1st%20semester/CSSS%20441%20Software%20Security/projects/KPI%20and%20certificate%20lifecycle%20manager/docs/report/project-report.md) | Entire Group 7 Team |

---

## 👥 Group 7 Technical Team & Module Allocation

* **Arnold Niikoi Djanie** (`1692642491`) — **Team Lead & PKI Architect**  
  * *Focus:* Module 1 (Two-Tier CA Hierarchy, Key Ceremony, Name Constraints & Path-Length Limits).
* **Peter Myles Etroo** (`1703154270`) — **ACME & Lab Infrastructure Lead**  
  * *Focus:* Module 2 (step-ca ACME provisioner, zero-downtime automated rotation for 5+ NGINX services).
* **Aaron Tettey-Fio** (`1704456123`) — **Revocation & Crypto Engineer**  
  * *Focus:* Module 3 (RFC 5280 CRL, RFC 6960 OCSP Responder, Failure-Injection test suite).
* **Osei Elvis** (`1703105081`) — **Backend & Inventory Service Lead**  
  * *Focus:* Module 4 (FastAPI backend, PostgreSQL parameterized repository, active TLS scanner).
* **Daniel Odame Lartey** (`1692180365`) — **Dashboard, Alerts & CT Lead**  
  * *Focus:* Module 5 (Auto-escaped Web Dashboard & Telegram/Email alerts) & Module 6 (Certificate Transparency via `crt.sh`).
* **Edinam Afi Ezuh** (`1700135424`) — **TLS Grading & Security QA Lead**  
  * *Focus:* Module 7 (TLS policy engine, `testssl.sh` scanning, Semgrep CI and OWASP negative tests).

---

## 🔒 Security Standards & Compliance Index

Every document in this directory strictly adheres to:
1. **OWASP ASVS 5.0 (Level 2):** Input sanitization, parameterized queries, and secure session headers.
2. **RFC 5280 & RFC 6960:** Internet X.509 Public Key Infrastructure and Online Certificate Status Protocol.
3. **RFC 8555:** Automatic Certificate Management Environment (ACME).
4. **Cybersecurity Act, 2020 (Act 1038):** Ethical bounds restricting all scanning to group-owned containers.
5. **Data Protection Act, 2012 (Act 843):** Telemetry privacy preserving zero personal identifying information.
