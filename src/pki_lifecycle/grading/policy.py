"""
TLS Configuration Policy Engine and Grading Module.
Responsible: Edinam Afi Ezuh (Module 7: TLS Policy & Grading)

SECURITY MANDATE:
- Policy check flags any service supporting below TLS 1.2.
- Enforces modern Authenticated Encryption with Associated Data (AEAD) cipher suites.
- Flags legacy cipher suites (CBC mode, RC4, 3DES).
"""

from typing import Any, Dict, List, Tuple


class TLSGradingEngine:
    """
    Evaluates TLS endpoint configurations against enterprise security policy.
    """

    MINIMUM_TLS_VERSION = "TLSv1.2"
    AEAD_CIPHER_KEYWORDS = ("GCM", "POLY1305", "CHACHA20", "CCM")

    @classmethod
    def evaluate_configuration(
        cls, tls_version: str, cipher_suite: str
    ) -> Tuple[str, List[str]]:
        """
        Grades the TLS configuration:
        - Grade A: TLS 1.3 or TLS 1.2 with AEAD ciphers
        - Grade B: TLS 1.2 with legacy ciphers (CBC)
        - Grade F: TLS 1.0 or TLS 1.1 (Immediate Policy Violation)
        """
        findings = []

        if tls_version in ("TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"):
            findings.append(f"CRITICAL: Obsolete protocol {tls_version} detected. Minimum required is TLS 1.2.")
            return "F", findings

        is_aead = any(k in cipher_suite.upper() for k in cls.AEAD_CIPHER_KEYWORDS)
        if not is_aead:
            findings.append(f"WARNING: Non-AEAD cipher suite '{cipher_suite}' in use. CBC ciphers are deprecated.")

        if tls_version == "TLSv1.3":
            return "A+", findings

        if tls_version == "TLSv1.2":
            if is_aead:
                return "A", findings
            return "B", findings

        findings.append(f"UNKNOWN: Unrecognized protocol version {tls_version}.")
        return "C", findings
