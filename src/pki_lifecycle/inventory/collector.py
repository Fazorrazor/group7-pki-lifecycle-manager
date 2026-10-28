"""
TLS Endpoint Scanner and Inventory Collector.
Responsible: Osei Elvis (Module 4: TLS Inventory Service)
"""

import socket
import ssl
from typing import Any, Dict, Optional
from datetime import datetime, timezone


class TLSInventoryCollector:
    """
    Connects to monitored TLS endpoints and collects X.509 certificate metadata.
    """

    def __init__(self, timeout_seconds: float = 5.0):
        self.timeout = timeout_seconds

    def probe_endpoint(self, hostname: str, port: int) -> Dict[str, Any]:
        """
        Initiates a TLS handshake and extracts certificate fields.
        """
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Initial discovery probe to detect expired/self-signed certs

        try:
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert() or {}
                    cipher = ssock.cipher()
                    tls_version = ssock.version()

                    return {
                        "status": "online",
                        "hostname": hostname,
                        "port": port,
                        "tls_version": tls_version,
                        "cipher": cipher,
                        "subject": cert_dict.get("subject", ()),
                        "issuer": cert_dict.get("issuer", ()),
                        "notBefore": cert_dict.get("notBefore", ""),
                        "notAfter": cert_dict.get("notAfter", ""),
                        "sans": cert_dict.get("subjectAltName", ()),
                    }
        except Exception as err:
            return {
                "status": "error",
                "hostname": hostname,
                "port": port,
                "error_message": str(err),
            }
