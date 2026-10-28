"""
Unit tests verifying parameterized query safety in the data-access layer.
Proves immunity to SQL Injection attacks (CWE-89).
"""

from pki_lifecycle.database.repository import CertificateRepository


def test_add_endpoint_with_sqli_payload_neutralized(repo: CertificateRepository):
    """
    Verifies that a SQL injection payload stored via parameterized query is safely
    treated as a literal string and does not alter the SQL structure or execute commands.
    """
    sqli_hostname = "test.internal' OR '1'='1"
    sqli_service = "service'); DROP TABLE endpoints;--"

    endpoint_id = repo.add_endpoint(
        hostname=sqli_hostname,
        port=8443,
        service_name=sqli_service,
        environment="lab",
    )
    assert endpoint_id > 0

    # Retrieve and verify the literal payload was preserved safely without tampering
    retrieved = repo.get_endpoint_by_hostname(sqli_hostname)
    assert retrieved is not None
    assert retrieved["hostname"] == sqli_hostname
    assert retrieved["service_name"] == sqli_service

    # Verify that the table was NOT dropped!
    all_endpoints = repo.search_endpoints_by_service("DROP TABLE")
    assert len(all_endpoints) == 1


def test_certificate_recording_and_revocation(repo: CertificateRepository):
    """
    Verifies parameterized certificate insertion and revocation status update.
    """
    serial = "a1b2c3d4e5f60718"
    repo.record_certificate(
        serial_number=serial,
        common_name="auth.lab.internal",
        issuer="Group 7 Intermediate CA",
        sans="auth.lab.internal,login.lab.internal",
        key_type="ECDSA",
        key_size=256,
        valid_from="2026-10-01 00:00:00",
        valid_to="2026-10-31 00:00:00",
        chain_complete=True,
    )

    revoked = repo.revoke_certificate(serial, "key_compromise")
    assert revoked is True

    # Test parameterized search
    cursor = repo.conn.cursor()
    cursor.execute("SELECT is_revoked, revocation_reason FROM certificates WHERE serial_number = ?", (serial,))
    row = cursor.fetchone()
    assert row["is_revoked"] == 1
    assert row["revocation_reason"] == "key_compromise"
