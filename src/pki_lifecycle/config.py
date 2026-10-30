"""
Security and Application Configuration
Adheres to 12-factor app principles and deny-by-default software security practices.
"""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    environment: str = os.getenv("ENVIRONMENT", "development")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    app_host: str = os.getenv("APP_HOST", "0.0.0.0")
    app_port: int = int(os.getenv("APP_PORT", "8000"))

    # Database Settings
    db_host: str = os.getenv("DB_HOST", "localhost")
    db_port: int = int(os.getenv("DB_PORT", "5432"))
    db_user: str = os.getenv("DB_USER", "pki_user")
    db_password: str = os.getenv("DB_PASSWORD", "change_this_in_production")
    db_name: str = os.getenv("DB_NAME", "pki_lifecycle_db")

    # Security policy constraints
    max_cert_lifespan_days: int = 30
    alert_days_thresholds: tuple[int, ...] = (30, 7, 1)
    min_tls_version: str = "TLSv1.2"

    # External Notifications
    telegram_bot_token: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
    telegram_chat_id: str = os.getenv("TELEGRAM_CHAT_ID", "")
    smtp_host: str = os.getenv("SMTP_HOST", "")
    smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
    alert_email_to: str = os.getenv("ALERT_EMAIL_TO", "")
    alert_email_from: str = os.getenv("ALERT_EMAIL_FROM", "")


settings = Settings()
