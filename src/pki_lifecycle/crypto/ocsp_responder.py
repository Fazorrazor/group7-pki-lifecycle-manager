"""
OCSP Responder Service (RFC 6960).
Responsible: Aaron Tettey-Fio (Module 3: Revocation Infrastructure)

Provides real-time revocation status validation using RFC 6960 signed OCSP responses
and JSON-based fast status queries.
"""

import datetime
from datetime import timezone
from typing import Any, Dict, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from pki_lifecycle.crypto.authority import TwoTierCA, ca_instance


class OCSPResponder:
    """
    Handles OCSP status requests and generates signed OCSP responses.
    """

    def __init__(self, ca: TwoTierCA = ca_instance):
        self.ca = ca

    def get_certificate_status(self, serial_number: int) -> Dict[str, Any]:
        """
        Returns JSON-friendly status dictionary for API clients.
        """
        hex_serial = format(serial_number, "x")
        if self.ca.is_revoked(serial_number):
            rev_time, reason = self.ca.revoked_serials[serial_number]
            return {
                "status": "revoked",
                "serial_number": hex_serial,
                "serial_int": serial_number,
                "revoked_at": rev_time.isoformat(),
                "reason": reason.name if hasattr(reason, "name") else str(reason),
                "responder": "Group 7 OCSP Responder",
            }
        return {
            "status": "good",
            "serial_number": hex_serial,
            "serial_int": serial_number,
            "responder": "Group 7 OCSP Responder",
        }

    def build_ocsp_response_bytes(
        self,
        cert: x509.Certificate,
        issuer_cert: Optional[x509.Certificate] = None,
    ) -> bytes:
        """
        Builds a standard DER-encoded signed RFC 6960 OCSP response.
        """
        if issuer_cert is None:
            issuer_cert = self.ca.intermediate_cert

        now = datetime.datetime.now(timezone.utc)
        serial = cert.serial_number

        if self.ca.is_revoked(serial):
            rev_time, reason = self.ca.revoked_serials[serial]
            builder = ocsp.OCSPResponseBuilder().add_response(
                cert=cert,
                issuer=issuer_cert,
                algorithm=hashes.SHA256(),
                cert_status=ocsp.OCSPCertStatus.REVOKED,
                this_update=now,
                next_update=now + datetime.timedelta(hours=1),
                revocation_time=rev_time,
                revocation_reason=reason,
            )
        else:
            builder = ocsp.OCSPResponseBuilder().add_response(
                cert=cert,
                issuer=issuer_cert,
                algorithm=hashes.SHA256(),
                cert_status=ocsp.OCSPCertStatus.GOOD,
                this_update=now,
                next_update=now + datetime.timedelta(hours=1),
                revocation_time=None,
                revocation_reason=None,
            )

        response = builder.responder_id(
            ocsp.OCSPResponderEncoding.HASH, issuer_cert
        ).sign(self.ca.intermediate_key, hashes.SHA256())

        return response.public_bytes(serialization.Encoding.DER)


ocsp_responder = OCSPResponder()
