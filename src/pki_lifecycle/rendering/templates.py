"""
Safe UI and report rendering engine with strict context-aware auto-escaping.
Responsible: Daniel Odame Lartey (Task 3: Week 2 Input-Handling Kit)

SECURITY MANDATE:
- All output rendering MUST enforce auto-escaping (autoescape=True).
- Mitigates CWE-79 (Cross-Site Scripting / XSS) and CWE-1336 (SSTI).
- Any untrusted endpoint input, certificate attribute, or user parameter is escaped.
"""

import html
from typing import Any, Dict, List


class SafeRenderer:
    """
    Renders HTML components and alerts for the certificate lifecycle dashboard.
    Enforces contextual HTML escaping on all dynamic data.
    """

    @staticmethod
    def escape_text(value: Any) -> str:
        """
        Escapes dynamic text input replacing characters &, <, >, ", ' with safe HTML entities.
        """
        if value is None:
            return ""
        return html.escape(str(value), quote=True)

    @classmethod
    def render_endpoint_row(cls, endpoint: Dict[str, Any]) -> str:
        """
        Renders a table row for an endpoint with complete attribute escaping.
        """
        safe_id = cls.escape_text(endpoint.get("id", ""))
        safe_hostname = cls.escape_text(endpoint.get("hostname", ""))
        safe_port = cls.escape_text(endpoint.get("port", ""))
        safe_service = cls.escape_text(endpoint.get("service_name", ""))
        safe_env = cls.escape_text(endpoint.get("environment", ""))

        return (
            f"<tr>"
            f"<td>{safe_id}</td>"
            f"<td class='hostname'>{safe_hostname}</td>"
            f"<td>{safe_port}</td>"
            f"<td>{safe_service}</td>"
            f"<td><span class='badge badge-{safe_env}'>{safe_env}</span></td>"
            f"</tr>"
        )

    @classmethod
    def render_certificate_card(cls, cert: Dict[str, Any]) -> str:
        """
        Renders a certificate details card with auto-escaping.
        """
        safe_serial = cls.escape_text(cert.get("serial_number", ""))
        safe_cn = cls.escape_text(cert.get("common_name", ""))
        safe_issuer = cls.escape_text(cert.get("issuer", ""))
        safe_sans = cls.escape_text(cert.get("sans", ""))
        safe_valid_to = cls.escape_text(cert.get("valid_to", ""))
        is_revoked = bool(cert.get("is_revoked", False))

        status_class = "danger" if is_revoked else "success"
        status_label = "REVOKED" if is_revoked else "ACTIVE"

        return (
            f"<div class='cert-card border-{status_class}'>"
            f"<h3>{safe_cn}</h3>"
            f"<p><strong>Serial:</strong> <code>{safe_serial}</code></p>"
            f"<p><strong>Issuer:</strong> {safe_issuer}</p>"
            f"<p><strong>SANs:</strong> {safe_sans}</p>"
            f"<p><strong>Expires:</strong> {safe_valid_to}</p>"
            f"<span class='status-pill {status_class}'>{status_label}</span>"
            f"</div>"
        )

    @classmethod
    def render_alert_banner(cls, message: str, level: str = "warning") -> str:
        """
        Renders an alert notification banner ensuring message payload cannot execute scripts.
        """
        safe_msg = cls.escape_text(message)
        safe_level = cls.escape_text(level)
        return f"<div class='alert alert-{safe_level}' role='alert'>{safe_msg}</div>"

    @classmethod
    def render_certificate_table_row(cls, cert: Dict[str, Any]) -> str:
        """
        Renders a rich table row for a certificate in the inventory table.
        """
        safe_serial = cls.escape_text(str(cert.get("serial_number", ""))[:16] + "...")
        full_serial = cls.escape_text(str(cert.get("serial_number", "")))
        safe_cn = cls.escape_text(cert.get("common_name", ""))
        safe_issuer = cls.escape_text(cert.get("issuer", ""))
        safe_valid_to = cls.escape_text(str(cert.get("valid_to", ""))[:19])
        is_revoked = bool(cert.get("is_revoked", False))
        chain_complete = bool(cert.get("chain_complete", True))

        # Status badge
        if is_revoked:
            status_badge = "<span class='badge badge-danger'>REVOKED</span>"
        else:
            status_badge = "<span class='badge badge-success'>ACTIVE</span>"

        # Chain badge
        chain_badge = (
            "<span class='badge badge-chain-ok'>Chain OK</span>"
            if chain_complete
            else "<span class='badge badge-danger'>Broken Chain</span>"
        )

        return (
            f"<tr>"
            f"<td><code title='{full_serial}'>{safe_serial}</code></td>"
            f"<td><strong>{safe_cn}</strong></td>"
            f"<td>{safe_issuer}</td>"
            f"<td>{safe_valid_to}</td>"
            f"<td>{chain_badge}</td>"
            f"<td>{status_badge}</td>"
            f"</tr>"
        )

    @classmethod
    def render_alert_row(cls, alert: Dict[str, Any]) -> str:
        """
        Renders an alert item in the live notification stream.
        """
        safe_time = cls.escape_text(alert.get("timestamp", ""))
        safe_title = cls.escape_text(alert.get("title", ""))
        safe_msg = cls.escape_text(alert.get("message", ""))
        safe_sev = cls.escape_text(alert.get("severity", "info"))
        safe_host = cls.escape_text(alert.get("endpoint_hostname", ""))

        sev_class = "danger" if safe_sev == "critical" else ("warning" if safe_sev == "warning" else "info")

        return (
            f"<div class='alert-card alert-{sev_class}'>"
            f"<div class='alert-header'>"
            f"<span class='badge badge-{sev_class}'>{safe_sev.upper()}</span>"
            f"<span class='alert-host'>{safe_host}</span>"
            f"<span class='alert-time'>{safe_time}</span>"
            f"</div>"
            f"<div class='alert-title'>{safe_title}</div>"
            f"<div class='alert-body'>{safe_msg}</div>"
            f"</div>"
        )

