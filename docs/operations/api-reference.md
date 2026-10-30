# REST API Specification & Endpoint Reference

**Course:** CSSS 441 Software Security I  
**Project:** Project 7 — Private PKI and Certificate Lifecycle Manager  
**Group:** Group 7  
**Module:** Module 4 (Backend Services & API Architecture)  
**Lead:** Osei Elvis (Student ID: `1703105081`)  

---

## 1. API Architecture & General Principles

The PKI Lifecycle Manager exposes a hardened RESTful API conforming to OpenAPI 3.0 / FastAPI standards. 

### Core Security Attributes
* **Input Validation:** Every payload is strictly validated using Pydantic schemas enforcing regex matching, max-length limits, and type safety.
* **HTTP Security Headers:** All responses include `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security`, and restrictive `Content-Security-Policy`.
* **Standard Response Format:** JSON responses utilize UTF-8 encoding. Revocation lists and OCSP responses provide raw cryptographic formats (`application/pkix-crl` and `application/ocsp-response`) alongside JSON inspectability.

---

## 2. System & Health Endpoints

### `GET /health`
Validates container health, service availability, and database connectivity.
* **Response (200 OK):**
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

## 3. Inventory & Fleet Scanning Endpoints

### `POST /api/v1/scan`
Triggers an immediate scan cycle across all registered lab endpoints.
* **Response (200 OK):**
```json
{
  "scan_id": "scan_20261029_183000",
  "timestamp": "2026-10-29T18:30:00Z",
  "total_scanned": 5,
  "compliant_count": 5,
  "non_compliant_count": 0,
  "results": [
    {
      "hostname": "auth.internal.lab",
      "port": 8443,
      "service_name": "auth-service",
      "serial_number": "3f8a1290e4b1",
      "is_compliant": true,
      "days_until_expiry": 29,
      "chain_complete": true,
      "violations": []
    }
  ]
}
```

### `GET /api/v1/endpoints`
Returns the complete list of registered TLS endpoints.

---

## 4. Certificate Issuance & Revocation Endpoints

### `POST /api/v1/certificates/issue`
Requests issuance of an end-entity certificate from the online Intermediate CA.
* **Policy Rule:** `validity_days` cannot exceed 30 days.
* **Request Payload (`CertificateIssueRequest`):**
```json
{
  "common_name": "vault.internal.lab",
  "sans": [
    "vault.internal.lab",
    "localhost"
  ],
  "validity_days": 14
}
```
* **Validation Failure (400 Bad Request):**
```json
{
  "detail": "Lifespan policy violation: 45 days exceeds mandatory 30-day cap"
}
```
* **Success (201 Created):**
```json
{
  "status": "issued",
  "serial_number": "5a7b8c9d0e1f",
  "common_name": "vault.internal.lab",
  "sans": ["vault.internal.lab", "localhost"],
  "valid_from": "2026-10-29T18:00:00Z",
  "valid_to": "2026-11-12T18:00:00Z",
  "validity_days": 14,
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "intermediate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
}
```

### `POST /api/v1/certificates/revoke`
Submits a certificate serial number for immediate revocation.
* **Request Payload (`RevocationRequest`):**
```json
{
  "serial_number": "5a7b8c9d0e1f",
  "reason": "key_compromise"
}
```
* **Allowed Reasons:** `key_compromise`, `ca_compromise`, `affiliation_changed`, `superseded`, `cessation_of_operation`.
* **Success (200 OK):**
```json
{
  "status": "revoked",
  "serial_number": "5a7b8c9d0e1f",
  "revoked_at": "2026-10-29T18:32:00Z",
  "reason": "key_compromise"
}
```

---

## 5. Revocation Infrastructure (RFC 5280 CRL & RFC 6960 OCSP)

### `GET /api/v1/crl`
Returns the signed Certificate Revocation List (CRL) in PEM format.
* **Content-Type:** `application/x-pem-file` or `application/pkix-crl`
* **Response Body:**
```
-----BEGIN X509 CRL-----
MIIBfDCB1AIBATANBgkqhkiG9w0BAQsFADBLMQswCQYDVQQGEwJHSDEhMB8GA1UE
...
-----END X509 CRL-----
```

### `GET /api/v1/ocsp/{serial_number}`
Fast, lightweight REST-based OCSP status interrogation for clients and scanners.
* **Response (200 OK):**
```json
{
  "serial_number": "5a7b8c9d0e1f",
  "status": "revoked",
  "revocation_time": "2026-10-29T18:32:00Z",
  "reason": "key_compromise",
  "this_update": "2026-10-29T18:32:00Z",
  "next_update": "2026-10-29T19:32:00Z"
}
```

### `POST /api/v1/ocsp`
Binary RFC 6960 compliant OCSP endpoint accepting standard DER requests from OpenSSL / curl.
* **Content-Type:** `application/ocsp-request`
* **Response Content-Type:** `application/ocsp-response`

---

## 6. Automated Renewal & Lifecycle Maintenance

### `POST /api/v1/renew`
Evaluates all services and executes zero-downtime rotation for certificates nearing expiry.
* **Query Parameters:** `threshold_days` (default: 7)
* **Response (200 OK):**
```json
{
  "renewed_count": 1,
  "threshold_days": 7,
  "rotations": [
    {
      "service_name": "billing-service",
      "hostname": "billing.internal.lab",
      "serial_number": "9d8e7f6a5b4c",
      "validity_days": 30,
      "downtime_seconds": 0.0,
      "status": "SUCCESS"
    }
  ]
}
```

---

## 7. Certificate Transparency Monitoring

### `GET /api/v1/ct/check`
Triggers external log synchronization against the `crt.sh` API for monitored domains (`.internal.lab`).
* **Response (200 OK):**
```json
{
  "monitored_domains": ["internal.lab", "group7-lab.org"],
  "total_logged": 12,
  "unauthorized_detected": 0,
  "audit_status": "CLEAN"
}
```
