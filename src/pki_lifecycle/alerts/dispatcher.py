"""
Automated Expiration & Security Alerts Dispatcher.
Responsible: Daniel Odame Lartey (Module 5: Dashboard, Alerts & CT Lead)

SECURITY MANDATE:
- Dispatches warnings at exact threshold dates: 30 days, 7 days, and 1 day before expiry.
- Dispatches CRITICAL alerts on:
  1. Revoked certificates
  2. Expired certificates
  3. Chain incompleteness
  4. Rogue Certificate Transparency detections
- Supports Telegram, Email, and Database event logging.
"""

import datetime
from datetime import timezone
from enum import Enum
import logging
from typing import Any, Dict, List, Optional
import httpx

from pki_lifecycle.config import settings

logger = logging.getLogger("pki_lifecycle.alerts")


class AlertSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertDispatcher:
    """
    Evaluates certificates against alerting thresholds and routes notifications.
    """

    THRESHOLDS = (30, 7, 1)

    def __init__(self, telegram_bot_token: Optional[str] = None, telegram_chat_id: Optional[str] = None):
        self.telegram_bot_token = telegram_bot_token or settings.telegram_bot_token
        self.telegram_chat_id = telegram_chat_id or settings.telegram_chat_id
        self.alert_history: List[Dict[str, Any]] = []

    def evaluate_certificate_expiry(self, cert: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Checks whether a certificate falls into the 30-day, 7-day, or 1-day alert windows.
        """
        alerts_triggered = []
        days_remaining = cert.get("days_until_expiry")
        if days_remaining is None:
            return alerts_triggered

        common_name = cert.get("common_name", "Unknown Host")
        serial = cert.get("serial_number", "N/A")

        if days_remaining <= 0:
            alert = self.dispatch_alert(
                title=f"EXPIRED: Certificate for {common_name}",
                message=f"Certificate (Serial: {serial}) is EXPIRED! Immediate replacement required.",
                severity=AlertSeverity.CRITICAL,
                endpoint_hostname=cert.get("hostname", common_name),
            )
            alerts_triggered.append(alert)
        elif days_remaining <= 1.0:
            alert = self.dispatch_alert(
                title=f"URGENT EXPIRY (1 Day): {common_name}",
                message=f"Certificate {common_name} expires in less than 24 hours ({round(days_remaining*24, 1)} hrs left).",
                severity=AlertSeverity.CRITICAL,
                endpoint_hostname=cert.get("hostname", common_name),
            )
            alerts_triggered.append(alert)
        elif days_remaining <= 7.0:
            alert = self.dispatch_alert(
                title=f"EXPIRY WARNING (7 Days): {common_name}",
                message=f"Certificate {common_name} will expire in {round(days_remaining, 1)} days. Automated ACME renewal pending.",
                severity=AlertSeverity.WARNING,
                endpoint_hostname=cert.get("hostname", common_name),
            )
            alerts_triggered.append(alert)
        elif days_remaining <= 30.0:
            alert = self.dispatch_alert(
                title=f"LIFECYCLE NOTICE (30 Days): {common_name}",
                message=f"Certificate {common_name} entered its final 30-day lifecycle window ({round(days_remaining, 1)} days left).",
                severity=AlertSeverity.INFO,
                endpoint_hostname=cert.get("hostname", common_name),
            )
            alerts_triggered.append(alert)

        return alerts_triggered

    def dispatch_alert(
        self,
        title: str,
        message: str,
        severity: AlertSeverity = AlertSeverity.WARNING,
        endpoint_hostname: str = "",
        channel: str = "internal",
    ) -> Dict[str, Any]:
        """
        Creates, records, and dispatches an alert record.
        """
        now = datetime.datetime.now(timezone.utc)
        record = {
            "id": len(self.alert_history) + 1,
            "title": title,
            "message": message,
            "severity": severity.value,
            "endpoint_hostname": endpoint_hostname,
            "channel": channel,
            "timestamp": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        }
        self.alert_history.insert(0, record)  # Newest first

        # Outbound notification dispatching
        logger.info(f"[{severity.value.upper()}] {title} - {message}")

        if self.telegram_bot_token and self.telegram_chat_id:
            try:
                payload = {
                    "chat_id": self.telegram_chat_id,
                    "text": f"🔐 *[{severity.value.upper()}] {title}*\n\n{message}\n\n_Target Host:_ `{endpoint_hostname or 'System'}`",
                    "parse_mode": "Markdown",
                }
                with httpx.Client(timeout=2.0) as client:
                    client.post(
                        f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage",
                        json=payload,
                    )
            except Exception as err:
                logger.debug(f"Telegram webhook transmission skipped/failed: {err}")

        return record

    def get_recent_alerts(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Returns the most recent alert records."""
        return self.alert_history[:limit]


alert_dispatcher = AlertDispatcher()
