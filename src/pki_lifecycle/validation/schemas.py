"""
Request validation schemas implementing OWASP input validation standards.
Responsible: Osei Elvis (Task 1: Week 2 Input-Handling Kit)
"""

import re
from enum import Enum
from typing import Annotated, List, Optional
from pydantic import BaseModel, Field, field_validator, model_validator


# RFC 1123 Hostname regex (strict, prevents command injection / path traversal)
HOSTNAME_REGEX = re.compile(
    r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
)

# Hexadecimal serial number regex
HEX_SERIAL_REGEX = re.compile(r"^[0-9a-fA-F]{8,64}$")


class KeyAlgorithm(str, Enum):
    RSA_2048 = "RSA-2048"
    RSA_4096 = "RSA-4096"
    ECDSA_P256 = "ECDSA-P256"
    ECDSA_P384 = "ECDSA-P384"
    ED25519 = "ED25519"


class RevocationReason(str, Enum):
    UNSPECIFIED = "unspecified"
    KEY_COMPROMISE = "key_compromise"
    CA_COMPROMISE = "ca_compromise"
    AFFILIATION_CHANGED = "affiliation_changed"
    SUPERSEDED = "superseded"
    CESSATION_OF_OPERATION = "cessation_of_operation"


class EndpointRegisterRequest(BaseModel):
    """
    Schema for onboarding a new internal TLS endpoint into the inventory monitor.
    Strictly validates hostname, port, and environmental tagging.
    """
    hostname: Annotated[
        str,
        Field(
            min_length=3,
            max_length=253,
            description="Fully qualified domain name or internal hostname (RFC 1123 compliant)",
            examples=["auth.internal.lab", "vault.service.internal"]
        )
    ]
    port: Annotated[
        int,
        Field(
            default=443,
            ge=1,
            le=65535,
            description="TCP port where TLS service is exposed"
        )
    ]
    service_name: Annotated[
        str,
        Field(
            min_length=2,
            max_length=64,
            pattern=r"^[a-zA-Z0-9_\-]+$",
            description="Alphanumeric identifier for the service without spaces or shell metacharacters"
        )
    ]
    environment: Annotated[
        str,
        Field(
            default="lab",
            pattern=r"^(lab|staging|production|internal)$",
            description="Environment tag restricted to known safe enums"
        )
    ]

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, v: str) -> str:
        v = v.strip().lower()
        if "\x00" in v or "\n" in v or "\r" in v:
            raise ValueError("Hostname contains forbidden control characters")
        if not HOSTNAME_REGEX.match(v):
            raise ValueError(f"Hostname '{v}' is not a valid RFC 1123 hostname")
        if len(v) > 253:
            raise ValueError("Hostname exceeds maximum allowable length of 253 characters")
        return v


class CertificateIssueRequest(BaseModel):
    """
    Schema for requesting a short-lived certificate via step-ca ACME workflow.
    Ensures certificates adhere to project max 30-day lifecycle rule.
    """
    common_name: Annotated[
        str,
        Field(min_length=3, max_length=64, description="Primary common name for X.509 cert")
    ]
    sans: Annotated[
        List[str],
        Field(
            default_factory=list,
            max_length=20,
            description="Subject Alternative Names (maximum 20 per certificate)"
        )
    ]
    key_algorithm: KeyAlgorithm = KeyAlgorithm.ECDSA_P256
    validity_days: Annotated[
        int,
        Field(
            default=30,
            ge=1,
            le=30,
            description="Certificate validity in days. Project security policy strictly caps this at 30 days"
        )
    ]
    contact_email: Annotated[
        Optional[str],
        Field(
            default=None,
            max_length=254,
            pattern=r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$",
            description="Contact email for expiry notifications"
        )
    ]

    @field_validator("common_name")
    @classmethod
    def validate_cn(cls, v: str) -> str:
        v = v.strip().lower()
        if not HOSTNAME_REGEX.match(v):
            raise ValueError(f"Common Name '{v}' must be a valid RFC 1123 hostname")
        return v

    @field_validator("sans")
    @classmethod
    def validate_sans(cls, sans: List[str]) -> List[str]:
        cleaned = []
        for san in sans:
            san_clean = san.strip().lower()
            if not HOSTNAME_REGEX.match(san_clean):
                raise ValueError(f"SAN '{san_clean}' is not a valid RFC 1123 hostname")
            cleaned.append(san_clean)
        return cleaned


class RevocationRequest(BaseModel):
    """
    Schema for revoking a compromised or superseded certificate.
    """
    serial_number: Annotated[
        str,
        Field(
            description="Hexadecimal serial number of the certificate to revoke",
            min_length=8,
            max_length=64
        )
    ]
    reason: RevocationReason = RevocationReason.KEY_COMPROMISE
    compromised_details: Annotated[
        Optional[str],
        Field(
            default=None,
            max_length=256,
            description="Brief explanation of incident; stripped of control chars"
        )
    ]

    @field_validator("serial_number")
    @classmethod
    def validate_serial(cls, v: str) -> str:
        v = v.strip().replace(":", "").lower()
        if not HEX_SERIAL_REGEX.match(v):
            raise ValueError("Serial number must be a valid hexadecimal string (8-64 chars)")
        return v

    @field_validator("compromised_details")
    @classmethod
    def sanitize_details(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        # Remove null bytes, control characters, or template tags
        cleaned = re.sub(r"[\x00-\x1f\x7f]", "", v).strip()
        return cleaned


class ScanTriggerRequest(BaseModel):
    """
    Schema for manually requesting a TLS endpoint scan cycle.
    """
    endpoint_id: Annotated[int, Field(ge=1, description="Positive database ID of the target endpoint")]
    force_rescan: bool = False
