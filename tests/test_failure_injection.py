"""
Automated Failure-Injection and Security Bar Verification Test Suite.
Course: CSSS 441 Software Security I (Project 7: Group 7)

Mandatory Security Bar Verifications:
1. Revoked certificate is refused via OCSP/CRL.
2. Expired certificate is detected within one scan cycle.
3. Wrong hostname (SAN mismatch) is detected within one scan cycle.
4. Missing intermediate chain is detected within one scan cycle.
5. Lifespan <= 30 days enforced at issuance.
6. Expiry alerts trigger at 30, 7, and 1-day thresholds.
7. Certificate Transparency monitor detects unauthorized/rogue CAs.
8. Zero-downtime automated certificate renewal.
"""

import datetime
from datetime import timezone
import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pki_lifecycle.acme.renewal import ACMERenewalManager
from pki_lifecycle.alerts.dispatcher import AlertDispatcher, AlertSeverity, alert_dispatcher
from pki_lifecycle.crypto.authority import TwoTierCA

from pki_lifecycle.crypto.ocsp_responder import OCSPResponder
from pki_lifecycle.ct_monitor.monitor import CTMonitor
from pki_lifecycle.inventory.collector import TLSInventoryCollector


@pytest.fixture
def test_pki():
    """Provides an isolated TwoTierCA instance for tests."""
    return TwoTierCA(base_domain="internal.lab")


# ============================================================================
# Security Bar Verification 1: Revoked Certificate Refused
# ============================================================================

def test_01_client_refuses_revoked_certificate_via_ocsp(test_pki):
    """Proves client and responder verify that a revoked certificate is detected and refused."""
    cert, _, chain = test_pki.issue_certificate("auth.internal.lab", ["auth.internal.lab"], validity_days=14)
    responder = OCSPResponder(ca=test_pki)
    collector = TLSInventoryCollector(ca=test_pki)

    # Initial state: Good
    status_before = responder.get_certificate_status(cert.serial_number)
    assert status_before["status"] == "good"

    # Revoke certificate
    test_pki.revoke_certificate(cert.serial_number, reason=x509.ReasonFlags.key_compromise)

    # OCSP query reflects revoked
    status_after = responder.get_certificate_status(cert.serial_number)
    assert status_after["status"] == "revoked"
    assert status_after["reason"] == "key_compromise"

    # Scan analysis flags revocation violation
    analysis = collector.analyze_certificate(cert, "auth.internal.lab", chain=chain)
    assert any("REVOKED" in v for v in analysis["violations"])
    assert analysis["is_compliant"] is False



# ============================================================================
# Security Bar Verification 2: Expired Certificate Detected Within 1 Cycle
# ============================================================================

def test_02_scanner_detects_expired_certificate(test_pki):
    """Proves expired certificates are detected and reported within one scan cycle."""
    now = datetime.datetime.now(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired.internal.lab")])

    # Build certificate with validity in the past
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(test_pki.intermediate_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=40))
        .not_valid_after(now - datetime.timedelta(days=10))
        .sign(test_pki.intermediate_key, hashes.SHA256())
    )

    collector = TLSInventoryCollector()
    analysis = collector.analyze_certificate(cert, "expired.internal.lab")

    assert any("EXPIRED" in v for v in analysis["violations"])
    assert analysis["is_compliant"] is False


# ============================================================================
# Security Bar Verification 3: Wrong Hostname (SAN Mismatch) Detected
# ============================================================================

def test_03_scanner_detects_wrong_hostname(test_pki):
    """Proves a certificate presented on a mismatched hostname is detected within one scan cycle."""
    cert, _, chain = test_pki.issue_certificate("billing.internal.lab", ["billing.internal.lab"], validity_days=20)
    collector = TLSInventoryCollector()

    # Target host does not match cert common name or SANs
    analysis = collector.analyze_certificate(cert, "vault.internal.lab", chain=chain)

    assert any("WRONG_HOSTNAME" in v for v in analysis["violations"])
    assert analysis["is_compliant"] is False


# ============================================================================
# Security Bar Verification 4: Missing Intermediate Chain Detected
# ============================================================================

def test_04_scanner_detects_missing_intermediate_chain(test_pki):
    """Proves TLS server failing to serve the full intermediate CA chain is detected."""
    cert, _, _ = test_pki.issue_certificate("portal.internal.lab", ["portal.internal.lab"], validity_days=25)
    collector = TLSInventoryCollector()

    # Pass empty chain / incomplete chain (leaf only)
    analysis = collector.analyze_certificate(cert, "portal.internal.lab", chain=[cert])

    assert any("MISSING_INTERMEDIATE" in v for v in analysis["violations"])
    assert analysis["chain_complete"] is False
    assert analysis["is_compliant"] is False


# ============================================================================
# Security Bar Verification 5: Lifespan <= 30 Days Strictly Enforced
# ============================================================================

def test_05_max_30_day_lifespan_enforcement(test_pki):
    """Proves that certificate requests exceeding 30-day lifespan policy are rejected."""
    with pytest.raises(ValueError) as excinfo:
        test_pki.issue_certificate("metrics.internal.lab", ["metrics.internal.lab"], validity_days=90)
    assert "exceeds 30-day max" in str(excinfo.value)


# ============================================================================
# Security Bar Verification 6: Expiration Alerts at 30, 7, and 1 Days
# ============================================================================

def test_06_expiry_alert_thresholds():
    """Proves alerts fire at 30 days, 7 days, and 1 day remaining."""
    dispatcher = AlertDispatcher()

    # Case A: 25 days remaining (falls into <=30 day window)
    alerts_30 = dispatcher.evaluate_certificate_expiry({"common_name": "app1.lab", "days_until_expiry": 25.0})
    assert len(alerts_30) == 1
    assert "30 Days" in alerts_30[0]["title"]
    assert alerts_30[0]["severity"] == AlertSeverity.INFO.value

    # Case B: 5 days remaining (falls into <=7 day window)
    alerts_7 = dispatcher.evaluate_certificate_expiry({"common_name": "app2.lab", "days_until_expiry": 5.0})
    assert len(alerts_7) == 1
    assert "7 Days" in alerts_7[0]["title"]
    assert alerts_7[0]["severity"] == AlertSeverity.WARNING.value

    # Case C: 0.5 days remaining (falls into <=1 day critical window)
    alerts_1 = dispatcher.evaluate_certificate_expiry({"common_name": "app3.lab", "days_until_expiry": 0.5})
    assert len(alerts_1) == 1
    assert "1 Day" in alerts_1[0]["title"]
    assert alerts_1[0]["severity"] == AlertSeverity.CRITICAL.value


# ============================================================================
# Security Bar Verification 7: Certificate Transparency Detection
# ============================================================================

def test_07_ct_monitoring_flags_unauthorized_issuer():
    """Proves Certificate Transparency monitoring detects rogue CAs issuing certs."""
    monitor = CTMonitor()
    finding = monitor.simulate_rogue_certificate("internal.lab", rogue_ca="Compromised Commercial CA")

    assert finding["flagged"] is True
    assert finding["is_authorized"] is False
    assert any("CT ROGUE CERT ALERT" in a["title"] for a in alert_dispatcher.alert_history)




# ============================================================================
# Security Bar Verification 8: Zero-Downtime Auto-Renewal
# ============================================================================

def test_08_zero_downtime_auto_renewal(test_pki):
    """Proves automated rotation provisions new valid certs with zero downtime recorded."""
    manager = ACMERenewalManager(ca=test_pki)
    dep = manager.provision_service_certificate("auth.internal.lab", "auth-service", validity_days=30)

    assert dep["rotation_status"] == "active_zero_downtime"
    assert len(manager.renewal_logs) == 1
    assert manager.renewal_logs[0]["downtime_seconds"] == 0.0
    assert manager.renewal_logs[0]["status"] == "SUCCESS"


# ============================================================================
# Security Bar Verification 9: Two-Tier CA Path Length and Constraints
# ============================================================================

def test_09_two_tier_ca_constraints(test_pki):
    """Verifies that Root CA has pathlen=1 and Intermediate CA enforces pathlen=0 and Name Constraints."""
    # Check Root CA basic constraints
    root_bc = test_pki.root_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert root_bc.ca is True
    assert root_bc.path_length == 1

    # Check Intermediate CA basic constraints
    int_bc = test_pki.intermediate_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert int_bc.ca is True
    assert int_bc.path_length == 0  # Cannot sign other CAs

    # Check Intermediate CA name constraints
    nc = test_pki.intermediate_cert.extensions.get_extension_for_class(x509.NameConstraints).value
    subtrees = [s.value for s in nc.permitted_subtrees]
    assert ".internal.lab" in subtrees or "internal.lab" in subtrees
