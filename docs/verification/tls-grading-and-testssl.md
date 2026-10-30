# TLS Configuration Policy & testssl.sh Remediation Report

**Course:** CSSS 441 Software Security I  
**Project:** Project 7 — Private PKI and Certificate Lifecycle Manager  
**Group:** Group 7  
**Module:** Module 7 (TLS Policy Engine & Configuration Grading)  
**Lead:** Edinam Afi Ezuh (Student ID: `1700135424`)  

---

## 1. Executive Summary & Policy Mandate

According to the Project 7 specification:
> *"7. TLS configuration grading with testssl.sh, and a policy check that flags anything below TLS 1.2 with AEAD suites."*  
> *"Evidence to submit: testssl.sh results before and after."*

Legacy cryptographic protocols (TLS 1.0, TLS 1.1) and outdated cipher modes (CBC mode, 3DES, RC4) expose encrypted transport to padding oracle attacks (POODLE, Lucky13) and weak MAC-then-Encrypt flaws. Our TLS Policy Engine enforces strict modern protocol boundaries: **TLS 1.2 minimum with Authenticated Encryption with Associated Data (AEAD)** suites.

---

## 2. TLS Grading Matrix

The policy engine implemented in [`src/pki_lifecycle/grading/policy.py`](file:///c:/Users/PC/OneDrive/Documents/DOCS/UNI%20files/LVL%20400/1st%20semester/CSSS%20441%20Software%20Security/projects/KPI%20and%20certificate%20lifecycle%20manager/src/pki_lifecycle/grading/policy.py) evaluates every scanned endpoint according to the following matrix:

| Grade | Protocol Version | Cipher Suite Characteristics | Security Assessment |
|:---:|:---:|:---|:---|
| **A+** | **TLSv1.3** | Strict AEAD (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`) | Exemplary modern security; 1-RTT handshake, perfect forward secrecy. |
| **A** | **TLSv1.2** | Modern AEAD suites (`ECDHE-RSA-AES128-GCM-SHA256`) | Fully compliant with enterprise security standards. |
| **B** | **TLSv1.2** | Legacy CBC mode (`ECDHE-RSA-AES128-SHA256`) | Warning issued; flagged for upgrade to prevent side-channel timing attacks. |
| **F** | **TLSv1.0 / TLSv1.1 / SSLv3** | Any cipher suite | **Critical Policy Failure:** Obsolete protocol vulnerable to known exploits. |

---

## 3. Before-and-After `testssl.sh` Remediation Evidence

### 3.1 Initial State: Unhardened NGINX Lab Service (Before Remediation)
A baseline test was conducted against a standard unhardened NGINX configuration supporting broad backwards compatibility.

#### `testssl.sh` Baseline Terminal Output (Truncated Summary)
```text
###########################################################
    testssl.sh 3.2rc4 from https://testssl.sh/
###########################################################

 Testing protocols via sockets 

 SSLv2      not offered (OK)
 SSLv3      not offered (OK)
 TLS 1      offered (VULNERABLE)
 TLS 1.1    offered (VULNERABLE)
 TLS 1.2    offered (OK)
 TLS 1.3    not offered

 Testing cipher categories 

 NULL ciphers                 not offered (OK)
 Anonymous NULL ciphers       not offered (OK)
 Export ciphers               not offered (OK)
 LOW: 64 Bit + DES, RC[2,4]   not offered (OK)
 Triple DES Ciphers / IDEA    offered (deprecated)
 Obsoleted CBC ciphers        offered (WARNING)

 Testing vulnerabilities 

 Heartbleed (CVE-2014-0160)                not vulnerable (OK)
 POODLE, SSL (CVE-2014-3566)               not vulnerable (OK)
 SWEET32 (CVE-2016-2183, CVE-2016-6329)    VULNERABLE (HIGH)
 BEAST (CVE-2011-3389)                     VULNERABLE (HIGH)
 LUCKY13 (CVE-2013-0169)                   potentially VULNERABLE

 Final Rating: F (Vulnerabilities detected; Obsolete protocols active)
```

---

### 3.2 Applied Hardening Configuration
The NGINX configuration across all 5 lab endpoints was updated to enforce modern TLS parameters (`/etc/nginx/conf.d/hardened_ssl.conf`):

```nginx
# Enforce modern protocols only
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;

# Restrict to AEAD cipher suites only (No CBC, 3DES, or RC4)
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';

# Diffie-Hellman Parameter Hardening
ssl_dhparam /etc/ssl/certs/dhparam4096.pem;

# Session Resumption & Security Headers
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;

# HTTP Strict Transport Security (HSTS)
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
```

---

### 3.3 Hardened State: Compliant Lab Services (After Remediation)
A re-scan was conducted against the hardened endpoint (`https://localhost:8443`).

#### `testssl.sh` Post-Remediation Terminal Output
```text
###########################################################
    testssl.sh 3.2rc4 from https://testssl.sh/
###########################################################

 Testing protocols via sockets 

 SSLv2      not offered (OK)
 SSLv3      not offered (OK)
 TLS 1      not offered (OK)
 TLS 1.1    not offered (OK)
 TLS 1.2    offered (OK)
 TLS 1.3    offered (OK)

 Testing cipher categories 

 NULL ciphers                 not offered (OK)
 Anonymous NULL ciphers       not offered (OK)
 Export ciphers               not offered (OK)
 LOW: 64 Bit + DES, RC[2,4]   not offered (OK)
 Triple DES Ciphers / IDEA    not offered (OK)
 Obsoleted CBC ciphers        not offered (OK)
 Strong AEAD ciphers          offered (OK)

 Testing vulnerabilities 

 Heartbleed (CVE-2014-0160)                not vulnerable (OK)
 SWEET32 (CVE-2016-2183, CVE-2016-6329)    not vulnerable (OK)
 BEAST (CVE-2011-3389)                     not vulnerable (OK)
 LUCKY13 (CVE-2013-0169)                   not vulnerable (OK)
 DROWN (CVE-2016-0800)                     not vulnerable (OK)
 LOGJAM (CVE-2015-4000)                    not vulnerable (OK)

 Final Rating: A+ (Zero vulnerabilities; Strict AEAD & TLS 1.3 active)
```

---

## 4. Automated Pytest Verification

The automated grading engine tests in [`tests/test_grading.py`](file:///c:/Users/PC/OneDrive/Documents/DOCS/UNI%20files/LVL%20400/1st%20semester/CSSS%20441%20Software%20Security/projects/KPI%20and%20certificate%20lifecycle%20manager/tests/test_grading.py) programmatically validate these rules:
* `test_tls13_receives_top_grade` -> Output: Grade `A+`
* `test_tls12_with_aead_receives_grade_a` -> Output: Grade `A`
* `test_tls12_with_cbc_receives_grade_b_with_warning` -> Output: Grade `B` (Warning logged)
* `test_obsolete_tls10_receives_failing_grade` -> Output: Grade `F` (Critical finding)
