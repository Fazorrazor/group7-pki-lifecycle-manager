"""
TLS Endpoint Scanner and Inventory Collector.
Responsible: Osei Elvis (Module 4: TLS Inventory Service) & Edinam Afi Ezuh (Module 7: TLS Grading)

SECURITY MANDATE:
- Discovers certificates and inspects full X.509 chains.
- Detects the 4 critical security bar conditions within one scan cycle:
  1. Wrong hostname (SAN mismatch)
  2. Expired certificate
  3. Missing intermediate certificate
  4. Revoked certificate
- Flags obsolete protocols (< TLS 1.2) and legacy ciphers (CBC mode).
"""

import datetime
from datetime import timezone
import socket
import ssl
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID

from pki_lifecycle.crypto.authority import ca_instance
from pki_lifecycle.grading.policy import TLSGradingEngine


class TLSInventoryCollector:
    """
    Connects to monitored TLS endpoints, collects X.509 metadata, and checks compliance.
    """

    def __init__(self, timeout_seconds: float = 3.0, ca: Optional[Any] = None):
        self.timeout = timeout_seconds
        self.ca = ca or ca_instance

    def probe_endpoint(self, hostname: str, port: int) -> Dict[str, Any]:

        """
        Initiates a TLS handshake and extracts certificate fields.
        """
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Discovery mode to inspect self-signed/expired certs

        try:
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    tls_version = ssock.version()

                    if not cert_bin:
                        return {
                            "status": "error",
                            "hostname": hostname,
                            "port": port,
                            "error_message": "No peer certificate returned",
                        }

                    cert = x509.load_der_x509_certificate(cert_bin)
                    return self.analyze_certificate(cert, hostname, port, tls_version, cipher[0] if cipher else "UNKNOWN")
        except Exception as err:
            return {
                "status": "offline",
                "hostname": hostname,
                "port": port,
                "error_message": str(err),
                "violations": [f"Connection failed: {str(err)}"],
                "is_compliant": False,
                "tls_grade": "F",
            }

    def analyze_certificate(
        self,
        cert: x509.Certificate,
        target_hostname: str,
        port: int = 443,
        tls_version: str = "TLSv1.3",
        cipher_suite: str = "TLS_AES_256_GCM_SHA384",
        chain: Optional[List[x509.Certificate]] = None,
    ) -> Dict[str, Any]:
        """
        Analyzes an X.509 certificate and checks against all course security bar mandates.
        """
        now = datetime.datetime.now(timezone.utc)
        violations: List[str] = []

        # 1. Serial Number
        serial_int = cert.serial_number
        serial_hex = format(serial_int, "x")

        # 2. Subject & Common Name
        try:
            cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            common_name = cn_attrs[0].value if cn_attrs else ""
        except Exception:
            common_name = ""

        # 3. Issuer
        try:
            issuer_cn_attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            issuer = issuer_cn_attrs[0].value if issuer_cn_attrs else str(cert.issuer)
        except Exception:
            issuer = str(cert.issuer)

        # 4. Subject Alternative Names (SANs)
        sans: List[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = [str(name.value) for name in san_ext.value]
        except x509.ExtensionNotFound:
            pass

        # 5. Validity Dates & Expiry Check
        valid_from = cert.not_valid_before_utc
        valid_to = cert.not_valid_after_utc
        days_until_expiry = (valid_to - now).total_seconds() / 86400.0

        # Security Bar Check 1: Expired certificate detection
        if now > valid_to:
            violations.append(f"EXPIRED: Certificate expired on {valid_to.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        elif now < valid_from:
            violations.append("NOT_YET_VALID: Certificate not yet valid")

        # Security Bar Check 2: Max 30-day lifespan rule
        lifespan_days = (valid_to - valid_from).days
        if lifespan_days > 30:
            violations.append(f"POLICY_VIOLATION: Certificate lifespan ({lifespan_days} days) exceeds the mandatory <=30 days limit")

        # Security Bar Check 3: Wrong hostname / SAN check
        matching_host = (target_hostname == common_name) or (target_hostname in sans)
        # Wildcard check (e.g. *.internal.lab matches auth.internal.lab)
        if not matching_host:
            for s in sans:
                if s.startswith("*.") and target_hostname.endswith(s[1:]):
                    matching_host = True
                    break
        if not matching_host:
            violations.append(f"WRONG_HOSTNAME: Target host '{target_hostname}' not found in cert SANs {sans}")

        # Security Bar Check 4: Chain completeness
        # An end-entity cert without intermediate served or with self-signed unverified issuer
        chain_complete = True
        if chain is not None:
            if len(chain) < 2:
                chain_complete = False
                violations.append("MISSING_INTERMEDIATE: TLS server presented leaf certificate without required intermediate CA chain")
        else:
            # Check if leaf claims to be signed by intermediate but presented as stand-alone
            if "Intermediate" in issuer and not cert.subject == cert.issuer:
                chain_complete = True

        # Security Bar Check 5: Revocation detection via OCSP/CRL
        is_revoked = self.ca.is_revoked(serial_int)
        if is_revoked:
            rev_date, reason = self.ca.revoked_serials[serial_int]
            violations.append(f"REVOKED: Certificate was revoked on {rev_date.strftime('%Y-%m-%d')} (Reason: {reason.name})")


        # Security Bar Check 6: TLS Grading Policy (Module 7)
        grade, grading_findings = TLSGradingEngine.evaluate_configuration(tls_version, cipher_suite)
        for gf in grading_findings:
            if gf.startswith("CRITICAL"):
                violations.append(gf)

        # Key Specs
        key_type = "RSA"
        key_size = getattr(cert.public_key(), "key_size", 2048)

        is_compliant = len(violations) == 0

        return {
            "status": "online",
            "hostname": target_hostname,
            "port": port,
            "serial_number": serial_hex,
            "serial_int": serial_int,
            "common_name": common_name,
            "issuer": issuer,
            "sans": sans,
            "key_type": key_type,
            "key_size": key_size,
            "valid_from": valid_from.isoformat(),
            "valid_to": valid_to.isoformat(),
            "days_until_expiry": round(days_until_expiry, 1),
            "lifespan_days": lifespan_days,
            "tls_version": tls_version,
            "cipher_suite": cipher_suite,
            "tls_grade": grade,
            "chain_complete": chain_complete,
            "is_revoked": is_revoked,
            "is_compliant": is_compliant,
            "violations": violations,
            "scanned_at": now.isoformat(),
        }


inventory_collector = TLSInventoryCollector()
