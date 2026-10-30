"""
Two-Tier Certificate Authority & Crypto Management Engine.
Responsible: Arnold Niikoi Djanie (Module 1: PKI Architect) & Aaron Tettey-Fio (Module 3: Revocation)

SECURITY SPECIFICATION:
- Tier 1: Offline Root CA (4096-bit RSA or P-384, basicConstraints CA:TRUE, pathlen:1)
- Tier 2: Online Intermediate CA (signed by Root, basicConstraints CA:TRUE, pathlen:0, Name Constraints)
- End-Entity Certificates: Issued with lifespan <= 30 days, SAN extension mandatory
- Revocation: RFC 5280 CRL and RFC 6960 OCSP response generation
"""

import datetime
from datetime import timezone
from typing import List, Optional, Tuple
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID


class TwoTierCA:
    """
    Manages the offline Root CA, online Intermediate CA, issuance, and revocation.
    """

    def __init__(self, base_domain: str = "internal.lab"):
        self.base_domain = base_domain
        self.root_key: RSAPrivateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
        self.intermediate_key: RSAPrivateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.root_cert = self._create_root_ca()
        self.intermediate_cert = self._create_intermediate_ca()
        self.revoked_serials: dict[int, Tuple[datetime.datetime, x509.ReasonFlags]] = {}

    def _create_root_ca(self) -> x509.Certificate:
        """
        Creates the Offline Root CA certificate with pathlen=1.
        """
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GH"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CSSS441 Group 7 Lab PKI"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Group 7 Offline Root CA"),
        ])
        now = datetime.datetime.now(timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))  # 10 years
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=1),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.root_key.public_key()),
                critical=False,
            )
        )
        return builder.sign(self.root_key, hashes.SHA256())

    def _create_intermediate_ca(self) -> x509.Certificate:
        """
        Creates the Online Intermediate CA signed by Root CA with pathlen=0 and Name Constraints.
        """
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GH"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CSSS441 Group 7 Lab PKI"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Group 7 Online Intermediate CA"),
        ])
        now = datetime.datetime.now(timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.root_cert.subject)
            .public_key(self.intermediate_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1825))  # 5 years
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),  # Strictly pathlen=0
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.NameConstraints(
                    permitted_subtrees=[
                        x509.DNSName(f".{self.base_domain}"),
                        x509.DNSName(self.base_domain),
                        x509.DNSName("localhost"),
                    ],
                    excluded_subtrees=None,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.intermediate_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.root_key.public_key()),
                critical=False,
            )
        )
        return builder.sign(self.root_key, hashes.SHA256())

    def issue_certificate(
        self,
        common_name: str,
        sans: List[str],
        validity_days: int = 30,
        private_key: Optional[RSAPrivateKey] = None,
        include_chain: bool = True,
    ) -> Tuple[x509.Certificate, RSAPrivateKey, List[x509.Certificate]]:
        """
        Issues an end-entity certificate enforcing max 30-day lifespan rule.
        Returns (certificate, private_key, cert_chain).
        """
        if validity_days > 30:
            raise ValueError(f"Security bar policy violation: validity_days={validity_days} exceeds 30-day max")

        if private_key is None:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        now = datetime.datetime.now(timezone.utc)
        san_names = [x509.DNSName(common_name)]
        for san in sans:
            if san != common_name:
                san_names.append(x509.DNSName(san))

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GH"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CSSS441 Group 7 Lab Services"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.intermediate_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName(san_names),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.intermediate_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityInformationAccess([
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier("http://localhost:8000/api/v1/ocsp"),
                    )
                ]),
                critical=False,
            )
            .add_extension(
                x509.CRLDistributionPoints([
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier("http://localhost:8000/api/v1/crl")],
                        relative_name=None,
                        crl_issuer=None,
                        reasons=None,
                    )
                ]),
                critical=False,
            )
        )

        cert = builder.sign(self.intermediate_key, hashes.SHA256())
        chain = [self.intermediate_cert, self.root_cert] if include_chain else []
        return cert, private_key, chain

    def revoke_certificate(
        self,
        serial_number: int,
        reason: x509.ReasonFlags = x509.ReasonFlags.key_compromise,
    ) -> None:
        """
        Marks a certificate serial number as revoked in the CA database.
        """
        now = datetime.datetime.now(timezone.utc)
        self.revoked_serials[serial_number] = (now, reason)

    def is_revoked(self, serial_number: int) -> bool:
        """Checks if a serial number is currently revoked."""
        return serial_number in self.revoked_serials

    def generate_crl(self) -> x509.CertificateRevocationList:
        """
        Generates a signed RFC 5280 X.509 Certificate Revocation List (CRL).
        """
        now = datetime.datetime.now(timezone.utc)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.intermediate_cert.subject)
            .last_update(now)
            .next_update(now + datetime.timedelta(days=1))
        )

        for serial, (rev_time, reason) in self.revoked_serials.items():
            revoked_cert_builder = (
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(rev_time)
                .add_extension(x509.CRLReason(reason), critical=False)
            )
            builder = builder.add_revoked_certificate(revoked_cert_builder.build())

        return builder.sign(self.intermediate_key, hashes.SHA256())


# Singleton CA instance for active lifecycle operations
ca_instance = TwoTierCA()
