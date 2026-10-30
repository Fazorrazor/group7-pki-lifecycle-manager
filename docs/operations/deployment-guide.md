# Deployment & Operations Runbook

**Course:** CSSS 441 Software Security I  
**Project:** Project 7 — Private PKI and Certificate Lifecycle Manager  
**Group:** Group 7  
**Academic Requirement:** Stranger Deployability & Auditability (10 Marks Criteria)  

---

## 1. Overview & System Requirements

This guide provides exhaustive, step-by-step instructions allowing any independent evaluator, lecturer, or system auditor to deploy, interact with, test, and audit the **Private PKI & Certificate Lifecycle Manager** from a clean workstation using a single command.

### Minimum System Prerequisites
* **Operating System:** Linux (Ubuntu 22.04/24.04), macOS, or Windows 10/11 with WSL2 / PowerShell.
* **Container Runtime:** Docker Engine 24.0+ and Docker Compose v2.20+.
* **Python Runtime (for local development/tests):** Python 3.11, 3.12, or 3.13.
* **System Resources:** Minimum 4 GB RAM, 2 CPU cores, and 5 GB free disk space.
* **Network Connectivity:** Unrestricted local loopback interface.

---

## 2. Port Allocation & Service Map

The Docker Compose orchestration stack provisions 8 segregated containers on the internal bridge network (`pki-network`):

| Container Name | Service Role | Internal Port | Host Port | External Access URL |
| :--- | :--- | :---: | :---: | :--- |
| `pki-backend` | FastAPI Orchestrator & Inventory Engine | `8000` | `8000` | `http://localhost:8000/docs`<br>`http://localhost:8000/dashboard` |
| `pki-postgres` | PostgreSQL Database (ACID Store) | `5432` | `5432` | `localhost:5432` |
| `pki-step-ca` | Smallstep ACME & Intermediate CA | `9000` | `9000` | `https://localhost:9000/health` |
| `lab-auth-service` | Lab NGINX Endpoint #1 | `443` | `8443` | `https://localhost:8443` |
| `lab-billing-service`| Lab NGINX Endpoint #2 | `443` | `8444` | `https://localhost:8444` |
| `lab-vault-service` | Lab NGINX Endpoint #3 | `443` | `8445` | `https://localhost:8445` |
| `lab-metrics-service`| Lab NGINX Endpoint #4 | `443` | `8446` | `https://localhost:8446` |
| `lab-portal-service` | Lab NGINX Endpoint #5 | `443` | `8447` | `https://localhost:8447` |

---

## 3. One-Command Quickstart

Follow these steps to deploy the entire stack from a clean Git checkout:

```bash
# 1. Clone the repository and enter the directory
git clone <repository-url>
cd group7-private-pki

# 2. Copy the environment configuration
cp .env.example .env

# 3. Launch the full environment in detached mode
docker compose up --build -d
```

### Validating Stack Initialization
Check container statuses using Docker:
```bash
docker compose ps
```
*All 8 containers should report state `Up` or `Up (healthy)`.*

Check the application healthcheck endpoint:
```bash
curl -s http://localhost:8000/health | jq
```
Expected output:
```json
{
  "status": "healthy",
  "service": "pki-lifecycle-manager",
  "environment": "production",
  "ca_tier": "Two-Tier (Offline Root + Online Intermediate)",
  "security_bar": "Max 30-Day Lifespan & Automated Renewal Enforced"
}
```

---

## 4. Web Dashboard & Administrative UI

Open your browser and navigate to:
```
http://localhost:8000/dashboard
```

The interactive dashboard features:
1. **Fleet Health Summary:** Live cards detailing Total Endpoints, Compliant Certificates, Expiry Warnings ($\le 30$d, $\le 7$d, $\le 1$d), and Critical Policy Violations.
2. **Endpoint Inventory Table:** Real-time visibility into FQDN, Port, Certificate Serial, Days Until Expiry, Chain Completeness, and Compliance Status.
3. **Automated Renewal Activity Log:** Timestamped audit trail showing zero-downtime certificate rotation events.
4. **Trigger Scan Button:** Dispatches immediate background probing across all 5 lab services.

---

## 5. Local Development & Verification Execution

To run unit tests, failure-injection drills, and static analysis locally:

### 5.1 Setting Up Local Virtual Environment
```bash
# Create and activate virtual environment
python -m venv .venv

# On Linux / macOS:
source .venv/bin/activate

# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1

# Install project dependencies
pip install -e .
pip install pytest pytest-cov httpx semgrep
```

### 5.2 Running the Complete Automated Test Suite (38 Tests)
```bash
pytest tests/ -v
```
*Expected Result: 38 passed in ~12 seconds.*

Test coverage includes:
* **`tests/test_failure_injection.py`:** Verifies the 6 security bar mandates (OCSP refusal, expired cert detection, SAN mismatch, missing intermediate, 30-day cap, zero-downtime rotation).
* **`tests/test_validation_negative.py`:** 20 negative OWASP unit tests covering SQLi payloads, path traversal, shell characters, homoglyphs, and buffer overflows.
* **`tests/test_grading.py`:** Tests TLS 1.3, TLS 1.2 AEAD, CBC mode, and obsolete TLS 1.0 rejection.
* **`tests/test_rendering.py`:** Validates contextual auto-escaping against stored XSS injections.
* **`tests/test_database.py`:** Verifies 100% parameterized query execution against SQLi payloads.

### 5.3 Static Security Analysis (Semgrep)
Run the configured Semgrep rules to verify zero high-risk security flaws:
```bash
semgrep scan --config auto .
```

---

## 6. Common Administrative & Operational Workflows

### 6.1 Triggering an On-Demand Fleet Scan
```bash
curl -X POST http://localhost:8000/api/v1/scan | jq
```

### 6.2 Issuing a New End-Entity Certificate
```bash
curl -X POST http://localhost:8000/api/v1/certificates/issue \
  -H "Content-Type: application/json" \
  -d '{
    "common_name": "vault.internal.lab",
    "sans": ["vault.internal.lab", "localhost"],
    "validity_days": 14
  }' | jq
```

### 6.3 Revoking a Certificate (Simulating Key Compromise)
```bash
# Revoke using serial number
curl -X POST http://localhost:8000/api/v1/certificates/revoke \
  -H "Content-Type: application/json" \
  -d '{
    "serial_number": "<HEX_SERIAL_NUMBER>",
    "reason": "key_compromise"
  }' | jq
```

### 6.4 Querying OCSP Responder Status
```bash
# Direct HTTP GET OCSP lookup
curl -s http://localhost:8000/api/v1/ocsp/<HEX_SERIAL_NUMBER> | jq
```

---

## 7. Troubleshooting & FAQ

* **Port 5432 or 8000 Conflict:**  
  If local services occupy port 5432 or 8000, adjust the mapping in `.env` (e.g., `PORT=8080`) and re-run `docker compose up -d`.
* **Database Connection Retries:**  
  The `backend` container waits for PostgreSQL healthcheck (`pg_isready`). Allow 10–15 seconds on initial volume initialization.
* **Certificate Authority Trust Warnings:**  
  Because the lab uses a private Two-Tier CA, browsers will display self-signed warnings for `https://localhost:8443` until the `root-ca.crt` is imported into your OS/browser trust store.
