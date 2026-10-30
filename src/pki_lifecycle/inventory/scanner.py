"""
Automated Inventory Scanner Orchestrator.
Responsible: Osei Elvis (Module 4: Inventory Lead) & Edinam Afi Ezuh (Module 7: Security QA)

Coordinates live endpoint scanning, policy enforcement, database updates, and alert dispatching.
"""

import datetime
from datetime import timezone
from typing import Any, Dict, List

from pki_lifecycle.acme.renewal import acme_manager
from pki_lifecycle.alerts.dispatcher import alert_dispatcher, AlertSeverity
from pki_lifecycle.crypto.authority import ca_instance
from pki_lifecycle.database.repository import CertificateRepository
from pki_lifecycle.inventory.collector import inventory_collector


class InventoryScanner:
    """
    Executes scheduled and on-demand inventory scans across all registered services.
    """

    def __init__(self, repo: CertificateRepository):
        self.repo = repo

    def scan_all_endpoints(self) -> Dict[str, Any]:
        """
        Executes a complete scan cycle across all registered lab services.
        Detects expired, wrong hostname, revoked, or missing intermediate certs.
        """
        endpoints = self.repo.search_endpoints_by_service("")
        if not endpoints:
            # Seed default 5 lab services if inventory is empty
            self._seed_default_endpoints()
            endpoints = self.repo.search_endpoints_by_service("")

        scanned_count = 0
        violations_count = 0
        results: List[Dict[str, Any]] = []

        for ep in endpoints:
            scanned_count += 1
            hostname = ep["hostname"]
            port = ep["port"]

            # If service has an active deployment in our ACME manager, inspect it
            deployment = acme_manager.active_deployments.get(hostname)
            if deployment:
                cert = deployment["cert_object"]
                chain = deployment["chain_objects"]
                res = inventory_collector.analyze_certificate(
                    cert=cert,
                    target_hostname=hostname,
                    port=port,
                    tls_version="TLSv1.3",
                    cipher_suite="TLS_AES_256_GCM_SHA384",
                    chain=chain,
                )
            else:
                # Live network probe fallback
                res = inventory_collector.probe_endpoint(hostname, port)

            # Record certificate in database
            if res.get("serial_number"):
                self.repo.record_certificate(
                    serial_number=res["serial_number"],
                    common_name=res.get("common_name", hostname),
                    issuer=res.get("issuer", "Unknown"),
                    sans=",".join(res.get("sans", [])),
                    key_type=res.get("key_type", "RSA"),
                    key_size=res.get("key_size", 2048),
                    valid_from=res.get("valid_from", ""),
                    valid_to=res.get("valid_to", ""),
                    chain_complete=res.get("chain_complete", True),
                )

            # Check expiration thresholds (30d, 7d, 1d)
            alert_dispatcher.evaluate_certificate_expiry(res)

            # Check security bar violations
            violations = res.get("violations", [])
            if violations:
                violations_count += 1
                for v in violations:
                    alert_dispatcher.dispatch_alert(
                        title=f"SECURITY VIOLATION: {hostname}",
                        message=v,
                        severity=AlertSeverity.CRITICAL,
                        endpoint_hostname=hostname,
                        channel="scanner",
                    )

            results.append(res)

        return {
            "timestamp": datetime.datetime.now(timezone.utc).isoformat(),
            "scanned_endpoints": scanned_count,
            "violations_detected": violations_count,
            "overall_status": "COMPLIANT" if violations_count == 0 else "WARNINGS_FOUND",
            "results": results,
        }

    def _seed_default_endpoints(self) -> None:
        """Seeds the 5 mandatory lab endpoints into database."""
        for svc in acme_manager.LAB_SERVICES:
            try:
                self.repo.add_endpoint(
                    hostname=svc["hostname"],
                    port=svc["port"],
                    service_name=svc["service_name"],
                    environment="lab",
                )
            except Exception:
                pass
