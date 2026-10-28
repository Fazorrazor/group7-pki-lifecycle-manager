"""
OWASP Negative Unit Test Suite (20 Tests).
Fulfills Week 2 Practical Requirements:
- Task 4a (Aaron Tettey-Fio): 10 tests for quotes, SQLi payloads, malformed formats.
- Task 4b (Edinam Afi Ezuh): 10 tests for long strings, Unicode tricks, wrong types.
"""

import pytest
from pydantic import ValidationError

from pki_lifecycle.validation.schemas import (
    CertificateIssueRequest,
    EndpointRegisterRequest,
    RevocationRequest,
    ScanTriggerRequest,
)


# ============================================================================
# TASK 4a: Aaron Tettey-Fio (Quotes, SQLi Payloads, Malformed Formats)
# ============================================================================

def test_01_sqli_payload_in_hostname():
    """Test 1: SQL injection payload with quotes and OR 1=1 is rejected in hostname."""
    with pytest.raises(ValidationError):
        EndpointRegisterRequest(
            hostname="' OR '1'='1",
            port=443,
            service_name="auth-service",
        )


def test_02_sqli_stacked_query_in_service_name():
    """Test 2: Stacked query / SQL command injection is rejected in service name."""
    with pytest.raises(ValidationError):
        EndpointRegisterRequest(
            hostname="api.internal.lab",
            port=443,
            service_name="auth; DROP TABLE endpoints;--",
        )


def test_03_quote_injection_in_common_name():
    """Test 3: Double quotes and illegal characters are rejected in certificate common name."""
    with pytest.raises(ValidationError):
        CertificateIssueRequest(
            common_name='internal"service.lab',
            validity_days=30,
        )


def test_04_malformed_hostname_shell_metacharacters():
    """Test 4: Shell metacharacters ($() && ;) are rejected in hostname."""
    with pytest.raises(ValidationError):
        EndpointRegisterRequest(
            hostname="server$(whoami).internal",
            port=443,
            service_name="api",
        )


def test_05_malformed_hostname_leading_dash():
    """Test 5: Hostname with leading dash (RFC 1123 violation) is rejected."""
    with pytest.raises(ValidationError):
        EndpointRegisterRequest(
            hostname="-badhostname.internal.lab",
            port=443,
            service_name="api",
        )


def test_06_null_byte_injection_in_hostname():
    """Test 6: Null byte injection attempt (\x00) is rejected."""
    with pytest.raises(ValidationError):
        EndpointRegisterRequest(
            hostname="vault.internal.lab\x00.evil.com",
            port=443,
            service_name="vault",
        )


def test_07_malformed_hex_serial_number_non_hex():
    """Test 7: Certificate serial number containing non-hex characters (Z, X, !) is rejected."""
    with pytest.raises(ValidationError):
        RevocationRequest(
            serial_number="ZZ99FF00XX!",
            reason="key_compromise",
        )


def test_08_serial_number_too_short():
    """Test 8: Certificate serial number below minimum 8 hexadecimal digits is rejected."""
    with pytest.raises(ValidationError):
        RevocationRequest(
            serial_number="abc",
            reason="key_compromise",
        )


def test_09_invalid_validity_period_too_large():
    """Test 9: Validity period exceeding maximum 30-day policy is rejected."""
    with pytest.raises(ValidationError):
        CertificateIssueRequest(
            common_name="auth.internal.lab",
            validity_days=90,  # Max allowed is 30 days
        )


def test_10_invalid_validity_period_zero_or_negative():
    """Test 10: Zero or negative validity period is rejected."""
    with pytest.raises(ValidationError):
        CertificateIssueRequest(
            common_name="auth.internal.lab",
            validity_days=0,
        )


# ============================================================================
# TASK 4b: Edinam Afi Ezuh (Long Strings, Unicode Tricks, Wrong Types)
# ============================================================================

def test_11_buffer_overflow_hostname_too_long():
    """Test 11: Excessively long hostname (>253 chars, RFC 1123 limit) is rejected."""
    excessive_hostname = "a" * 254 + ".internal.lab"
    with pytest.raises(ValidationError):
        EndpointRegisterRequest(
            hostname=excessive_hostname,
            port=443,
            service_name="auth",
        )


def test_12_oversized_service_name():
    """Test 12: Oversized service name (>64 chars) is rejected."""
    oversized_name = "service_" + "x" * 100
    with pytest.raises(ValidationError):
        EndpointRegisterRequest(
            hostname="api.internal.lab",
            port=443,
            service_name=oversized_name,
        )


def test_13_unicode_homoglyph_in_hostname():
    """Test 13: Non-ASCII Cyrillic homoglyph character in hostname is rejected."""
    # Using Cyrillic 'а' (\u0430) instead of ASCII 'a'
    homoglyph_hostname = "v\u0430ult.internal.lab"
    with pytest.raises(ValidationError):
        EndpointRegisterRequest(
            hostname=homoglyph_hostname,
            port=443,
            service_name="vault",
        )


def test_14_unicode_zero_width_space_in_hostname():
    """Test 14: Zero-width space character (\u200B) in hostname is rejected."""
    sneaky_hostname = "auth\u200B.internal.lab"
    with pytest.raises(ValidationError):
        EndpointRegisterRequest(
            hostname=sneaky_hostname,
            port=443,
            service_name="auth",
        )


def test_15_wrong_type_port_string():
    """Test 15: Non-numeric string provided for port field is rejected."""
    with pytest.raises(ValidationError):
        EndpointRegisterRequest(
            hostname="api.internal.lab",
            port="four-four-three",  # type: ignore
            service_name="api",
        )


def test_16_wrong_type_port_out_of_range_high():
    """Test 16: Port exceeding maximum valid TCP port (65535) is rejected."""
    with pytest.raises(ValidationError):
        EndpointRegisterRequest(
            hostname="api.internal.lab",
            port=70000,
            service_name="api",
        )


def test_17_wrong_type_port_out_of_range_negative():
    """Test 17: Negative port number is rejected."""
    with pytest.raises(ValidationError):
        EndpointRegisterRequest(
            hostname="api.internal.lab",
            port=-443,
            service_name="api",
        )


def test_18_wrong_type_scan_endpoint_id_negative():
    """Test 18: Non-positive / negative endpoint ID is rejected."""
    with pytest.raises(ValidationError):
        ScanTriggerRequest(endpoint_id=-1)


def test_19_excessive_sans_array_flooding():
    """Test 19: Excessive SAN count (>20) to prevent resource exhaustion is rejected."""
    too_many_sans = [f"sub{i}.internal.lab" for i in range(25)]
    with pytest.raises(ValidationError):
        CertificateIssueRequest(
            common_name="root.internal.lab",
            sans=too_many_sans,
            validity_days=30,
        )


def test_20_wrong_type_validity_days_string():
    """Test 20: Alphabetic string given for validity_days integer field is rejected."""
    with pytest.raises(ValidationError):
        CertificateIssueRequest(
            common_name="auth.internal.lab",
            validity_days="invalid_days",  # type: ignore
        )
