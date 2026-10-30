import json
import uuid
import jsonschema
import urllib.request

def create_model():
    # UUIDs for cells
    id_root_ca = "11111111-0001-4000-8000-000000000001"
    id_step_ca = "11111111-0002-4000-8000-000000000002"
    id_endpoints = "11111111-0003-4000-8000-000000000003"
    id_ocsp = "11111111-0004-4000-8000-000000000004"
    id_inventory = "11111111-0005-4000-8000-000000000005"
    id_postgres = "11111111-0006-4000-8000-000000000006"
    id_dashboard = "11111111-0007-4000-8000-000000000007"
    id_ct = "11111111-0008-4000-8000-000000000008"

    # Boundaries
    id_tb1 = "22222222-0001-4000-8000-000000000001"
    id_tb2 = "22222222-0002-4000-8000-000000000002"

    # Flows
    id_f1 = "33333333-0001-4000-8000-000000000001"
    id_f2 = "33333333-0002-4000-8000-000000000002"
    id_f3 = "33333333-0003-4000-8000-000000000003"
    id_f4 = "33333333-0004-4000-8000-000000000004"
    id_f5 = "33333333-0005-4000-8000-000000000005"
    id_f6 = "33333333-0006-4000-8000-000000000006"
    id_f7 = "33333333-0007-4000-8000-000000000007"

    threat_count = 0
    def make_threat(title, stride_type, severity, description, mitigation):
        nonlocal threat_count
        threat_count += 1
        return {
            "id": str(uuid.uuid4()),
            "threatId": str(uuid.uuid4()),
            "number": threat_count,
            "title": title,
            "type": stride_type,
            "modelType": "STRIDE",
            "severity": severity,
            "status": "Open",
            "description": description,
            "mitigation": mitigation,
            "score": "High" if severity == "High" else "Medium"
        }

    # 12 Component STRIDE threats
    threats_root = [
        make_threat("Root CA Key Compromise", "Information disclosure", "High",
                    "Exfiltration of the offline Root CA private key invalidates the entire trust hierarchy.",
                    "Air-gap machine, strict documented multi-person key ceremony, physical USB custody logs.")
    ]
    threats_stepca = [
        make_threat("ACME Client Impersonation", "Spoofing", "High",
                    "Attacker spoofs an internal lab endpoint to request certificates for unauthorized hostnames.",
                    "ACME challenge validation restricted to internal DNS/HTTP-01 tokens and Name Constraints."),
        make_threat("Intermediate CA Key Exfiltration", "Information disclosure", "High",
                    "Unauthorized access to container or host filesystem exposes the intermediate private key.",
                    "File permissions, non-root container execution, pathlen:0 constraint.")
    ]
    threats_endpoints = [
        make_threat("Weak Cipher / Protocol Downgrade", "Information disclosure", "Medium",
                    "Misconfigured NGINX instance allows TLS 1.0/1.1 or CBC ciphers vulnerable to plaintext recovery.",
                    "Enforce TLS 1.3 / TLS 1.2 with AEAD only via automated testssl.sh policy scanner."),
        make_threat("Privilege Escalation via Unrestricted Cert Scope", "Elevation of privilege", "High",
                    "Issued certificate lacks path-length or name constraints, allowing client cert to sign subordinate certs.",
                    "Intermediate CA signs end-entity certs with BasicConstraints CA:FALSE and pathlen:0.")
    ]
    threats_ocsp = [
        make_threat("OCSP Replay / Tampering Attack", "Tampering", "High",
                    "Stale 'Good' OCSP response replayed to bypass revoked certificate enforcement.",
                    "OCSP nonces enabled and short validity window for OCSP responses."),
        make_threat("OCSP Responder DoS Leading to Fail-Open", "Denial of service", "High",
                    "Flooding OCSP responder causing clients to bypass revocation checks if soft-failing.",
                    "High availability, short CRL fallback caching, and rate limiting.")
    ]
    threats_inventory = [
        make_threat("SQL Injection in Endpoint Query Service", "Tampering", "High",
                    "Malicious search strings injected into endpoint lookup to extract or alter certificate database records.",
                    "Pydantic schema validation and strictly parameterized SQL queries in repository layer."),
        make_threat("Denial of Service via Scan Flooding", "Denial of service", "Medium",
                    "Attacker floods inventory scan endpoint with connection requests to exhaust server threads.",
                    "Per-IP rate limiting and asynchronous background task queuing.")
    ]
    threats_postgres = [
        make_threat("Direct Database Modification Bypassing Audit", "Repudiation", "Medium",
                    "Attacker with database access alters certificate status without logging in audit trails.",
                    "Append-only scan audit records and least-privilege DB connection credentials."),
        make_threat("Unauthorized Access to Stored Credentials", "Information disclosure", "High",
                    "Plaintext passwords or tokens in database exposed via unencrypted storage.",
                    "PostgreSQL TLS connections and environment variable secrets management.")
    ]
    threats_dashboard = [
        make_threat("Stored XSS via Certificate SANs", "Tampering", "High",
                    "Malicious payload embedded in certificate Common Name or SAN executed in admin browser dashboard.",
                    "Context-aware HTML auto-escaping for all certificate attributes rendered in UI."),
        make_threat("Alert Dispatch Tampering", "Tampering", "Medium",
                    "Expiry alert payloads modified in transit to suppress critical warning notifications.",
                    "TLS transport security for SMTP/Telegram webhook dispatchers.")
    ]
    threats_ct = [
        make_threat("Rogue Certificate Issuance Evasion", "Spoofing", "High",
                    "Rogue public CA certificate issued for organization domains without operator awareness.",
                    "Continuous automated querying of crt.sh API and instant alerts on unknown serial numbers.")
    ]

    # Threats explicitly attached to Boundary-Crossing Data Flows
    threats_flow1 = [
        make_threat("Malicious USB Drop / CSR Tampering (Air-Gap Crossing)", "Tampering", "High",
                    "Adversary tampers with the intermediate CSR or signed certificate payload on portable media crossing the air-gap boundary.",
                    "Dual-custody key ceremony, visual fingerprint comparison on air-gapped machine, cryptographic SHA-256 verifications.")
    ]
    threats_flow2 = [
        make_threat("ACME Challenge Hijacking (DMZ Crossing)", "Spoofing", "High",
                    "Attacker in DMZ intercepts or spoofs ACME HTTP-01/DNS-01 validation challenges crossing into the management CA zone.",
                    "Mutual TLS/token authentication for ACME clients, Name Constraints restricting domain issuance, and automated challenge expiry.")
    ]
    threats_flow3 = [
        make_threat("OCSP Response Replay / Stripping (DMZ Crossing)", "Tampering", "High",
                    "Man-in-the-middle on the DMZ boundary intercepts OCSP queries and replays expired 'Good' responses or drops packets to force soft-fail.",
                    "RFC 6960 OCSP nonces enforced, short OCSP validity cache (<= 1 hour), and strict client hard-fail policy on unreachable OCSP.")
    ]
    threats_flow4 = [
        make_threat("TLS Probing Interception / Forgery (DMZ Crossing)", "Information disclosure", "Medium",
                    "Untrusted entity on the DMZ boundary intercepts scanner probes or presents forged test certificates to hide real security posture.",
                    "Strict X.509 root-anchored chain verification during scans, client cert authentication, and tamper-evident scan audit logs.")
    ]
    threats_flow7 = [
        make_threat("CT Log Poisoning / Query Suppression (Internet Crossing)", "Tampering", "High",
                    "Adversary on the external Internet connection intercepts crt.sh API calls or returns forged empty responses to conceal rogue certificates.",
                    "TLS certificate pinning for crt.sh API, timeout alerts, and secondary log verifications across multiple CT providers.")
    ]

    cells = [
        # 1. Root CA (Process) - Top Left
        {
            "position": {"x": 50, "y": 120},
            "size": {"width": 130, "height": 90},
            "attrs": {
                "text": {"text": "Offline Root CA\n(Air-Gapped)"},
                "body": {"stroke": "#333333", "strokeWidth": 1, "strokeDasharray": "none"}
            },
            "shape": "process",
            "zIndex": 2,
            "id": id_root_ca,
            "data": {
                "name": "Offline Root CA\n(Air-Gapped)",
                "description": "Offline root certificate authority signing intermediate certificates only.",
                "type": "tm.Process",
                "isTrustBoundary": False,
                "outOfScope": False,
                "reasonOutOfScope": "",
                "hasOpenThreats": True,
                "threats": threats_root
            },
            "threats": threats_root
        },
        # 2. step-ca (Process) - Top Center
        {
            "position": {"x": 370, "y": 120},
            "size": {"width": 140, "height": 90},
            "attrs": {
                "text": {"text": "step-ca Online\nIntermediate CA"},
                "body": {"stroke": "#333333", "strokeWidth": 1, "strokeDasharray": "none"}
            },
            "shape": "process",
            "zIndex": 3,
            "id": id_step_ca,
            "data": {
                "name": "step-ca Online\nIntermediate CA",
                "description": "Online ACME Certificate Authority issuing short-lived leaf certificates (<=30 days).",
                "type": "tm.Process",
                "isTrustBoundary": False,
                "outOfScope": False,
                "reasonOutOfScope": "",
                "hasOpenThreats": True,
                "threats": threats_stepca
            },
            "threats": threats_stepca
        },
        # 3. NGINX Lab Web Services (Actor / Endpoints) - Top Right
        {
            "position": {"x": 800, "y": 120},
            "size": {"width": 160, "height": 85},
            "attrs": {
                "text": {"text": "NGINX Lab Services\n(5+ Endpoints)"},
                "body": {"stroke": "#333333", "strokeWidth": 1, "strokeDasharray": "none"}
            },
            "shape": "actor",
            "zIndex": 4,
            "id": id_endpoints,
            "data": {
                "name": "NGINX Lab Services\n(5+ Endpoints)",
                "description": "Containerized internal HTTPS endpoints managed by automated certbot/lego renewal.",
                "type": "tm.Actor",
                "isTrustBoundary": False,
                "outOfScope": False,
                "reasonOutOfScope": "",
                "hasOpenThreats": True,
                "providesAuthentication": True,
                "threats": threats_endpoints
            },
            "threats": threats_endpoints
        },
        # 4. OCSP Responder (Process) - Center Middle
        {
            "position": {"x": 370, "y": 280},
            "size": {"width": 140, "height": 90},
            "attrs": {
                "text": {"text": "OCSP / CRL\nResponder"},
                "body": {"stroke": "#333333", "strokeWidth": 1, "strokeDasharray": "none"}
            },
            "shape": "process",
            "zIndex": 5,
            "id": id_ocsp,
            "data": {
                "name": "OCSP / CRL\nResponder",
                "description": "Real-time revocation status responder (RFC 6960 OCSP and RFC 5280 CRL).",
                "type": "tm.Process",
                "isTrustBoundary": False,
                "outOfScope": False,
                "reasonOutOfScope": "",
                "hasOpenThreats": True,
                "threats": threats_ocsp
            },
            "threats": threats_ocsp
        },
        # 5. FastAPI Inventory Engine (Process) - Bottom Center
        {
            "position": {"x": 370, "y": 480},
            "size": {"width": 140, "height": 90},
            "attrs": {
                "text": {"text": "FastAPI Inventory\n& Scanner"},
                "body": {"stroke": "#333333", "strokeWidth": 1, "strokeDasharray": "none"}
            },
            "shape": "process",
            "zIndex": 6,
            "id": id_inventory,
            "data": {
                "name": "FastAPI Inventory\n& Scanner",
                "description": "Active TLS scanner and inventory control plane backend.",
                "type": "tm.Process",
                "isTrustBoundary": False,
                "outOfScope": False,
                "reasonOutOfScope": "",
                "hasOpenThreats": True,
                "threats": threats_inventory
            },
            "threats": threats_inventory
        },
        # 6. PostgreSQL DB (Store) - Bottom Left
        {
            "position": {"x": 50, "y": 485},
            "size": {"width": 140, "height": 80},
            "attrs": {
                "text": {"text": "PostgreSQL DB\n(Cert Inventory)"},
                "topLine": {"stroke": "red", "strokeWidth": 2, "strokeDasharray": "none"},
                "bottomLine": {"stroke": "red", "strokeWidth": 2, "strokeDasharray": "none"}
            },
            "shape": "store",
            "zIndex": 7,
            "id": id_postgres,
            "data": {
                "name": "PostgreSQL DB\n(Cert Inventory)",
                "description": "Relational store for TLS endpoint certificates, scan histories, and revocation state.",
                "type": "tm.Store",
                "isTrustBoundary": False,
                "outOfScope": False,
                "reasonOutOfScope": "",
                "hasOpenThreats": True,
                "threats": threats_postgres
            },
            "threats": threats_postgres
        },
        # 7. Web Dashboard & Alerts (Process) - Bottom Mid-Right
        {
            "position": {"x": 690, "y": 480},
            "size": {"width": 150, "height": 90},
            "attrs": {
                "text": {"text": "Web Dashboard\n& Alerts (30d, 7d, 1d)"},
                "body": {"stroke": "#333333", "strokeWidth": 1, "strokeDasharray": "none"}
            },
            "shape": "process",
            "zIndex": 8,
            "id": id_dashboard,
            "data": {
                "name": "Web Dashboard\n& Alerts (30d, 7d, 1d)",
                "description": "Admin web interface for cert inventory, metrics, and automated expiry alerts.",
                "type": "tm.Process",
                "isTrustBoundary": False,
                "outOfScope": False,
                "reasonOutOfScope": "",
                "hasOpenThreats": True,
                "threats": threats_dashboard
            },
            "threats": threats_dashboard
        },
        # 8. Certificate Transparency Logs (Actor) - Bottom Right
        {
            "position": {"x": 1000, "y": 485},
            "size": {"width": 150, "height": 80},
            "attrs": {
                "text": {"text": "Certificate Transparency\n(crt.sh API)"},
                "body": {"stroke": "#333333", "strokeWidth": 1, "strokeDasharray": "none"}
            },
            "shape": "actor",
            "zIndex": 9,
            "id": id_ct,
            "data": {
                "name": "Certificate Transparency\n(crt.sh API)",
                "description": "Public Certificate Transparency log monitoring for rogue certificates.",
                "type": "tm.Actor",
                "isTrustBoundary": False,
                "outOfScope": False,
                "reasonOutOfScope": "",
                "hasOpenThreats": True,
                "providesAuthentication": False,
                "threats": threats_ct
            },
            "threats": threats_ct
        },

        # Trust Boundary 1: Air-Gapped Root CA Boundary
        {
            "shape": "trust-boundary-curve",
            "attrs": {
                "line": {
                    "stroke": "#e74c3c",
                    "strokeWidth": 2,
                    "strokeDasharray": "5 5",
                    "targetMarker": "",
                    "sourceMarker": ""
                }
            },
            "width": 200,
            "height": 100,
            "zIndex": 1,
            "connector": "smooth",
            "labels": [{"attrs": {"text": {"text": "Air-Gapped Root Boundary"}}}],
            "data": {
                "type": "tm.Boundary",
                "name": "Air-Gapped Root Boundary",
                "description": "Physical separation between offline Root CA and online networks",
                "isTrustBoundary": True,
                "hasOpenThreats": False
            },
            "id": id_tb1,
            "source": {"x": 260, "y": 50},
            "target": {"x": 260, "y": 400},
            "vertices": []
        },

        # Trust Boundary 2: Lab Services DMZ Boundary
        {
            "shape": "trust-boundary-curve",
            "attrs": {
                "line": {
                    "stroke": "#e74c3c",
                    "strokeWidth": 2,
                    "strokeDasharray": "5 5",
                    "targetMarker": "",
                    "sourceMarker": ""
                }
            },
            "width": 200,
            "height": 100,
            "zIndex": 1,
            "connector": "smooth",
            "labels": [{"attrs": {"text": {"text": "Lab Services DMZ Boundary"}}}],
            "data": {
                "type": "tm.Boundary",
                "name": "Lab Services DMZ Boundary",
                "description": "Network boundary isolating internal lab services from management control plane",
                "isTrustBoundary": True,
                "hasOpenThreats": False
            },
            "id": id_tb2,
            "source": {"x": 650, "y": 50},
            "target": {"x": 650, "y": 400},
            "vertices": []
        },

        # Data Flows
        # Flow 1: Root CA -> step-ca (CROSSES AIR-GAPPED BOUNDARY)
        {
            "shape": "flow",
            "attrs": {
                "line": {
                    "stroke": "#333333",
                    "strokeWidth": 1,
                    "targetMarker": {"name": "block"},
                    "strokeDasharray": "none"
                }
            },
            "width": 200,
            "height": 100,
            "zIndex": 10,
            "connector": "smooth",
            "data": {
                "type": "tm.Flow",
                "name": "1. Offline Sub-CA Signing",
                "description": "One-time offline signing of Intermediate CA certificate during key ceremony.",
                "outOfScope": False,
                "reasonOutOfScope": "",
                "protocol": "Air-gapped USB",
                "isEncrypted": False,
                "isPublicNetwork": False,
                "hasOpenThreats": True,
                "threats": threats_flow1,
                "isTrustBoundary": False
            },
            "id": id_f1,
            "labels": [{"position": 0.5, "attrs": {"label": {"text": "1. Offline Signing"}}}],
            "source": {"cell": id_root_ca},
            "target": {"cell": id_step_ca},
            "threats": threats_flow1
        },

        # Flow 2: step-ca <-> Endpoints (CROSSES DMZ BOUNDARY)
        {
            "shape": "flow",
            "attrs": {
                "line": {
                    "stroke": "#333333",
                    "strokeWidth": 1,
                    "targetMarker": {"name": "block"},
                    "strokeDasharray": "none"
                }
            },
            "width": 200,
            "height": 100,
            "zIndex": 10,
            "connector": "smooth",
            "data": {
                "type": "tm.Flow",
                "name": "2. ACME Auto-Renewal (<=30d)",
                "description": "Automated ACME certificate issuance and renewal via certbot/lego.",
                "outOfScope": False,
                "reasonOutOfScope": "",
                "protocol": "HTTPS (ACME)",
                "isEncrypted": True,
                "isPublicNetwork": False,
                "hasOpenThreats": True,
                "threats": threats_flow2,
                "isTrustBoundary": False
            },
            "id": id_f2,
            "labels": [{"position": 0.5, "attrs": {"label": {"text": "2. ACME Issuance & Renew"}}}],
            "source": {"cell": id_endpoints},
            "target": {"cell": id_step_ca},
            "threats": threats_flow2
        },

        # Flow 3: Endpoints -> OCSP (CROSSES DMZ BOUNDARY)
        {
            "shape": "flow",
            "attrs": {
                "line": {
                    "stroke": "#333333",
                    "strokeWidth": 1,
                    "targetMarker": {"name": "block"},
                    "strokeDasharray": "none"
                }
            },
            "width": 200,
            "height": 100,
            "zIndex": 10,
            "connector": "smooth",
            "data": {
                "type": "tm.Flow",
                "name": "3. OCSP Nonce & Revocation Check",
                "description": "Clients verify certificate revocation status via OCSP responder with nonces.",
                "outOfScope": False,
                "reasonOutOfScope": "",
                "protocol": "HTTP (OCSP)",
                "isEncrypted": False,
                "isPublicNetwork": False,
                "hasOpenThreats": True,
                "threats": threats_flow3,
                "isTrustBoundary": False
            },
            "id": id_f3,
            "labels": [{"position": 0.5, "attrs": {"label": {"text": "3. OCSP Revocation Check"}}}],
            "source": {"cell": id_endpoints},
            "target": {"cell": id_ocsp},
            "threats": threats_flow3
        },

        # Flow 4: FastAPI Inventory -> Endpoints (CROSSES DMZ BOUNDARY)
        {
            "shape": "flow",
            "attrs": {
                "line": {
                    "stroke": "#333333",
                    "strokeWidth": 1,
                    "targetMarker": {"name": "block"},
                    "strokeDasharray": "none"
                }
            },
            "width": 200,
            "height": 100,
            "zIndex": 10,
            "connector": "smooth",
            "data": {
                "type": "tm.Flow",
                "name": "4. TLS Probing & Scans",
                "description": "FastAPI scanner actively connects to TLS endpoints to record expiry and testssl.sh grade.",
                "outOfScope": False,
                "reasonOutOfScope": "",
                "protocol": "TLS 1.2/1.3",
                "isEncrypted": True,
                "isPublicNetwork": False,
                "hasOpenThreats": True,
                "threats": threats_flow4,
                "isTrustBoundary": False
            },
            "id": id_f4,
            "labels": [{"position": 0.5, "attrs": {"label": {"text": "4. TLS Inventory Probing"}}}],
            "source": {"cell": id_inventory},
            "target": {"cell": id_endpoints},
            "vertices": [{"x": 640, "y": 320}],
            "threats": threats_flow4
        },

        # Flow 5: FastAPI Inventory <-> PostgreSQL (Internal - No boundary crossing)
        {
            "shape": "flow",
            "attrs": {
                "line": {
                    "stroke": "#333333",
                    "strokeWidth": 1,
                    "targetMarker": {"name": "block"},
                    "strokeDasharray": "none"
                }
            },
            "width": 200,
            "height": 100,
            "zIndex": 10,
            "connector": "smooth",
            "data": {
                "type": "tm.Flow",
                "name": "5. Store / Query Cert Records",
                "description": "FastAPI repository layer writes certificate metadata and queries active inventory.",
                "outOfScope": False,
                "reasonOutOfScope": "",
                "protocol": "PostgreSQL Wire Protocol",
                "isEncrypted": True,
                "isPublicNetwork": False,
                "hasOpenThreats": False,
                "threats": [],
                "isTrustBoundary": False
            },
            "id": id_f5,
            "labels": [{"position": 0.5, "attrs": {"label": {"text": "5. Store / Fetch Metadata"}}}],
            "source": {"cell": id_inventory},
            "target": {"cell": id_postgres}
        },

        # Flow 6: Web Dashboard <-> FastAPI Inventory (Internal - No boundary crossing)
        {
            "shape": "flow",
            "attrs": {
                "line": {
                    "stroke": "#333333",
                    "strokeWidth": 1,
                    "targetMarker": {"name": "block"},
                    "strokeDasharray": "none"
                }
            },
            "width": 200,
            "height": 100,
            "zIndex": 10,
            "connector": "smooth",
            "data": {
                "type": "tm.Flow",
                "name": "6. API Inventory Queries",
                "description": "Dashboard queries endpoints, displays expiry charts, and dispatches alerts at 30, 7, 1 days.",
                "outOfScope": False,
                "reasonOutOfScope": "",
                "protocol": "HTTPS REST API",
                "isEncrypted": True,
                "isPublicNetwork": False,
                "hasOpenThreats": False,
                "threats": [],
                "isTrustBoundary": False
            },
            "id": id_f6,
            "labels": [{"position": 0.5, "attrs": {"label": {"text": "6. REST API & Alerts"}}}],
            "source": {"cell": id_dashboard},
            "target": {"cell": id_inventory}
        },

        # Flow 7: Web Dashboard / Alerts -> crt.sh (CROSSES EXTERNAL INTERNET BOUNDARY)
        {
            "shape": "flow",
            "attrs": {
                "line": {
                    "stroke": "#333333",
                    "strokeWidth": 1,
                    "targetMarker": {"name": "block"},
                    "strokeDasharray": "none"
                }
            },
            "width": 200,
            "height": 100,
            "zIndex": 10,
            "connector": "smooth",
            "data": {
                "type": "tm.Flow",
                "name": "7. Poll CT Logs",
                "description": "Monitoring service polls public crt.sh API to detect unauthorized or rogue public certificate issuance.",
                "outOfScope": False,
                "reasonOutOfScope": "",
                "protocol": "HTTPS GET",
                "isEncrypted": True,
                "isPublicNetwork": True,
                "hasOpenThreats": True,
                "threats": threats_flow7,
                "isTrustBoundary": False
            },
            "id": id_f7,
            "labels": [{"position": 0.5, "attrs": {"label": {"text": "7. Poll CT Logs (crt.sh)"}}}],
            "source": {"cell": id_dashboard},
            "target": {"cell": id_ct},
            "threats": threats_flow7
        }
    ]

    model = {
        "version": "2.0.0",
        "summary": {
            "title": "Project 7: Private PKI and Certificate Lifecycle Manager",
            "owner": "Group 7 (CSSS 441 Software Security I)",
            "description": "Threat model for two-tier private PKI, ACME automated certificate lifecycle manager, inventory scanner, and CT monitor.",
            "id": 0
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
            "diagramTop": 1,
            "reviewer": "Course Lecturer",
            "threatTop": threat_count,
            "diagrams": [
                {
                    "title": "Level-1 Data Flow Diagram (PKI & Lifecycle Manager)",
                    "thumbnail": "thumbnail.stride.jpg",
                    "diagramType": "STRIDE",
                    "id": 0,
                    "version": "2.0.0",
                    "cells": cells
                }
            ]
        }
    }

    return model

if __name__ == "__main__":
    m = create_model()
    # Validate against online schema
    schema = json.loads(urllib.request.urlopen('https://raw.githubusercontent.com/OWASP/threat-dragon/main/td.vue/src/assets/schema/threat-dragon-v2.schema.json').read())
    jsonschema.validate(instance=m, schema=schema)
    print("SUCCESS: 100% Valid against Threat Dragon v2 schema!")

    with open("docs/threat-model/threat-model.json", "w") as f:
        json.dump(m, f, indent=2)
    print("Written docs/threat-model/threat-model.json with threats on all boundary flows!")
