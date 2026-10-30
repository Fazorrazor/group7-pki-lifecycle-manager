import json
import uuid

# Helper to build consistent cells
def make_process(cid, name, x, y, width=160, height=100, threats=None, desc=""):
    return {
        "type": "tm.Process",
        "id": cid,
        "size": {"width": width, "height": height},
        "position": {"x": x, "y": y},
        "angle": 0,
        "z": 2,
        "hasOpenThreats": bool(threats),
        "description": desc or name,
        "threats": threats or [],
        "attrs": {
            ".element-shape": {
                "class": "element-shape hasOpenThreats isInScope" if threats else "element-shape hasNoOpenThreats isInScope"
            },
            "text": {
                "text": name
            },
            ".element-text": {
                "class": "element-text hasOpenThreats isInScope" if threats else "element-text hasNoOpenThreats isInScope"
            }
        }
    }

def make_actor(cid, name, x, y, width=160, height=80, threats=None, desc=""):
    return {
        "type": "tm.Actor",
        "id": cid,
        "size": {"width": width, "height": height},
        "position": {"x": x, "y": y},
        "angle": 0,
        "z": 2,
        "hasOpenThreats": bool(threats),
        "description": desc or name,
        "threats": threats or [],
        "attrs": {
            ".element-shape": {
                "class": "element-shape hasOpenThreats isInScope" if threats else "element-shape hasNoOpenThreats isInScope"
            },
            "text": {
                "text": name
            },
            ".element-text": {
                "class": "element-text hasOpenThreats isInScope" if threats else "element-text hasNoOpenThreats isInScope"
            }
        }
    }

def make_store(cid, name, x, y, width=160, height=80, threats=None, desc=""):
    return {
        "type": "tm.Store",
        "id": cid,
        "size": {"width": width, "height": height},
        "position": {"x": x, "y": y},
        "angle": 0,
        "z": 2,
        "hasOpenThreats": bool(threats),
        "description": desc or name,
        "threats": threats or [],
        "attrs": {
            ".element-shape": {
                "class": "element-shape hasOpenThreats isInScope" if threats else "element-shape hasNoOpenThreats isInScope"
            },
            "text": {
                "text": name
            },
            ".element-text": {
                "class": "element-text hasOpenThreats isInScope" if threats else "element-text hasNoOpenThreats isInScope"
            }
        }
    }

def make_flow(cid, source_id, target_id, label, desc="", z=5):
    return {
        "type": "tm.Flow",
        "id": cid,
        "size": {"width": 10, "height": 10},
        "smooth": True,
        "source": {"id": source_id},
        "target": {"id": target_id},
        "labels": [
            {
                "position": 0.5,
                "attrs": {
                    "text": {
                        "text": label,
                        "font-weight": "400",
                        "font-size": "small"
                    }
                }
            }
        ],
        "z": z,
        "hasOpenThreats": False,
        "description": desc or label,
        "attrs": {
            ".marker-target": {
                "class": "marker-target hasNoOpenThreats isInScope"
            },
            ".connection": {
                "class": "connection hasNoOpenThreats isInScope"
            }
        }
    }

def make_boundary(cid, name, sx, sy, tx, ty, z=1):
    return {
        "type": "tm.Boundary",
        "id": cid,
        "size": {"width": 10, "height": 10},
        "smooth": True,
        "source": {"x": sx, "y": sy},
        "target": {"x": tx, "y": ty},
        "z": z,
        "name": name,
        "attrs": {
            ".connection": {
                "stroke": "#e74c3c",
                "stroke-width": 2,
                "stroke-dasharray": "5 5"
            }
        }
    }

# Build model
cells = []

# Boundaries
cells.append(make_boundary("tb-offline", "Air-Gapped Root CA Boundary", 50, 40, 260, 40))
cells.append(make_boundary("tb-internal", "Internal Management Zone", 320, 40, 680, 40))
cells.append(make_boundary("tb-dmz", "Lab Services DMZ", 740, 40, 1050, 40))

# Elements
# 1. Root CA (Process / Offline CA)
cells.append(make_process(
    "proc-root",
    "Offline Root CA\n(Air-Gapped)",
    80, 120, 150, 90,
    threats=[
        {
            "threatId": str(uuid.uuid4()),
            "title": "Root CA Key Compromise",
            "type": "Information disclosure",
            "status": "Open",
            "severity": "High",
            "description": "Exfiltration of the offline Root CA private key invalidates the entire trust hierarchy.",
            "mitigation": "Air-gap machine, strict documented multi-person key ceremony, physical USB custody logs."
        }
    ],
    desc="Offline root certificate authority signing intermediate certificates only."
))

# 2. step-ca Intermediate CA
cells.append(make_process(
    "proc-stepca",
    "step-ca Online\nIntermediate CA",
    380, 120, 160, 90,
    threats=[
        {
            "threatId": str(uuid.uuid4()),
            "title": "ACME Client Impersonation",
            "type": "Spoofing",
            "status": "Open",
            "severity": "High",
            "description": "Attacker spoofs an internal lab endpoint to request certificates for unauthorized hostnames.",
            "mitigation": "ACME challenge validation restricted to internal DNS/HTTP-01 tokens and Name Constraints."
        },
        {
            "threatId": str(uuid.uuid4()),
            "title": "Intermediate CA Private Key Exfiltration",
            "type": "Information disclosure",
            "status": "Open",
            "severity": "High",
            "description": "Unauthorized access to the container or host filesystem exposes the intermediate private key.",
            "mitigation": "File permissions, non-root container execution, pathlen:0 constraint."
        }
    ],
    desc="Online ACME Certificate Authority issuing short-lived leaf certificates (<=30 days)."
))

# 3. NGINX Lab Web Services
cells.append(make_actor(
    "ext-endpoints",
    "NGINX Lab Services\n(5+ Endpoints)",
    800, 120, 170, 90,
    threats=[
        {
            "threatId": str(uuid.uuid4()),
            "title": "Weak Cipher / Protocol Downgrade",
            "type": "Information disclosure",
            "status": "Open",
            "severity": "Medium",
            "description": "Misconfigured NGINX instance allows TLS 1.0/1.1 or CBC ciphers vulnerable to plaintext recovery.",
            "mitigation": "Enforce TLS 1.3 / TLS 1.2 with AEAD only via automated testssl.sh policy scanner."
        },
        {
            "threatId": str(uuid.uuid4()),
            "title": "Privilege Escalation via Unrestricted Cert Scope",
            "type": "Elevation of privilege",
            "status": "Open",
            "severity": "High",
            "description": "Issued certificate lacks path-length or name constraints, allowing client cert to sign subordinate certs.",
            "mitigation": "Intermediate CA signs end-entity certs with BasicConstraints CA:FALSE and pathlen:0."
        }
    ],
    desc="Containerized internal HTTPS endpoints managed by automated certbot/lego renewal."
))

# 4. OCSP / CRL Responder
cells.append(make_process(
    "proc-ocsp",
    "OCSP / CRL\nResponder",
    380, 270, 160, 90,
    threats=[
        {
            "threatId": str(uuid.uuid4()),
            "title": "OCSP Replay / Tampering Attack",
            "type": "Tampering",
            "status": "Open",
            "severity": "High",
            "description": "Stale 'Good' OCSP response replayed to bypass revoked certificate enforcement.",
            "mitigation": "OCSP nonces enabled and short validity window for OCSP responses."
        },
        {
            "threatId": str(uuid.uuid4()),
            "title": "OCSP Responder DoS Leading to Fail-Open",
            "type": "Denial of service",
            "status": "Open",
            "severity": "High",
            "description": "Flooding OCSP responder causing clients to bypass revocation checks if soft-failing.",
            "mitigation": "High availability, short CRL fallback caching, and rate limiting."
        }
    ],
    desc="Real-time revocation status responder (RFC 6960 OCSP and RFC 5280 CRL)."
))

# 5. FastAPI Inventory Engine
cells.append(make_process(
    "proc-inventory",
    "FastAPI Inventory\n& Scanner",
    380, 440, 160, 90,
    threats=[
        {
            "threatId": str(uuid.uuid4()),
            "title": "SQL Injection in Endpoint Query Service",
            "type": "Tampering",
            "status": "Open",
            "severity": "High",
            "description": "Malicious search strings injected into endpoint lookup to extract or alter certificate database records.",
            "mitigation": "Pydantic schema validation and strictly parameterized SQL queries in repository layer."
        },
        {
            "threatId": str(uuid.uuid4()),
            "title": "Denial of Service via Scan Flooding",
            "type": "Denial of service",
            "status": "Open",
            "severity": "Medium",
            "description": "Attacker floods inventory scan endpoint with connection requests to exhaust server threads.",
            "mitigation": "Per-IP rate limiting and asynchronous background task queuing."
        }
    ],
    desc="Active TLS scanner and inventory control plane backend."
))

# 6. PostgreSQL Database
cells.append(make_store(
    "store-postgres",
    "PostgreSQL DB\n(Cert Inventory)",
    100, 440, 160, 90,
    threats=[
        {
            "threatId": str(uuid.uuid4()),
            "title": "Direct Database Modification Bypassing Audit",
            "type": "Repudiation",
            "status": "Open",
            "severity": "Medium",
            "description": "Attacker with database access alters certificate status without logging in audit trails.",
            "mitigation": "Append-only scan audit records and least-privilege DB connection credentials."
        },
        {
            "threatId": str(uuid.uuid4()),
            "title": "Unauthorized Access to Stored Credentials",
            "type": "Information disclosure",
            "status": "Open",
            "severity": "High",
            "description": "Plaintext passwords or tokens in database exposed via unencrypted storage.",
            "mitigation": "PostgreSQL TLS connections and environment variable secrets management."
        }
    ],
    desc="Relational store for TLS endpoint certificates, scan histories, and revocation state."
))

# 7. Web Dashboard & Alerts
cells.append(make_process(
    "proc-dashboard",
    "Web Dashboard\n& Alerts (30d, 7d, 1d)",
    650, 440, 160, 90,
    threats=[
        {
            "threatId": str(uuid.uuid4()),
            "title": "Stored Cross-Site Scripting (XSS) via Certificate SANs",
            "type": "Tampering",
            "status": "Open",
            "severity": "High",
            "description": "Malicious payload embedded in certificate Common Name or SAN executed in admin browser dashboard.",
            "mitigation": "Context-aware HTML auto-escaping for all certificate attributes rendered in UI."
        },
        {
            "threatId": str(uuid.uuid4()),
            "title": "Alert Dispatch Tampering",
            "type": "Tampering",
            "status": "Open",
            "severity": "Medium",
            "description": "Expiry alert payloads modified in transit to suppress critical warning notifications.",
            "mitigation": "TLS transport security for SMTP/Telegram webhook dispatchers."
        }
    ],
    desc="Admin web interface for cert inventory, metrics, and automated expiry alerts."
))

# 8. Certificate Transparency Logs
cells.append(make_actor(
    "ext-ct",
    "Certificate Transparency\n(crt.sh API)",
    920, 440, 160, 90,
    threats=[
        {
            "threatId": str(uuid.uuid4()),
            "title": "Rogue Certificate Issuance Evasion",
            "type": "Spoofing",
            "status": "Open",
            "severity": "High",
            "description": "Rogue public CA certificate issued for organization domains without operator awareness.",
            "mitigation": "Continuous automated querying of crt.sh API and instant alerts on unknown serial numbers."
        }
    ],
    desc="Public Certificate Transparency log monitoring for rogue certificates."
))

# Flows
cells.append(make_flow("flow-1", "proc-root", "proc-stepca", "1. Sign Intermediate CA (Offline)"))
cells.append(make_flow("flow-2", "proc-stepca", "ext-endpoints", "2. ACME Auto-Issuance & Renew (<=30d)"))
cells.append(make_flow("flow-3", "ext-endpoints", "proc-ocsp", "3. OCSP Nonce & Revocation Check"))
cells.append(make_flow("flow-4", "proc-inventory", "ext-endpoints", "4. TLS Probing & Compliance Scan"))
cells.append(make_flow("flow-5", "proc-inventory", "store-postgres", "5. Store/Query Cert Records"))
cells.append(make_flow("flow-6", "proc-dashboard", "proc-inventory", "6. API Inventory Queries"))
cells.append(make_flow("flow-7", "proc-dashboard", "ext-ct", "7. Poll CT Logs (crt.sh)"))

# Complete model document
model = {
    "version": "2.0",
    "summary": {
        "title": "Project 7: Private PKI and Certificate Lifecycle Manager",
        "owner": "Group 7 (CSSS 441 Software Security I)",
        "description": "Threat model for two-tier private PKI, ACME automated certificate lifecycle manager, inventory scanner, and CT monitor."
    },
    "detail": {
        "contributors": [
            {"name": "Arnold Niikoi Djanie"},
            {"name": "Peter Myles Etroo"},
            {"name": "Aaron Tettey-Fio"},
            {"name": "Osei Elvis"},
            {"name": "Daniel Odame Lartey"},
            {"name": "Edinam Afi Ezuh"}
        ],
        "diagrams": [
            {
                "title": "Level-1 Data Flow Diagram (PKI & Lifecycle Manager)",
                "id": 0,
                "diagramType": "STRIDE",
                "size": {"width": 1200, "height": 700},
                "diagramJson": {
                    "cells": cells
                },
                "cells": cells
            }
        ]
    }
}

with open("docs/threat-model/threat-model.json", "w") as f:
    json.dump(model, f, indent=2)

print("Successfully written updated Threat Dragon model with", len(cells), "cells!")

