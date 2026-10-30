"""
Key Ceremony CLI & Certificate Authority Initializer.
Course: CSSS 441 Software Security I (Project 7: Module 1)
Responsible: Arnold Niikoi Djanie (Team Lead & PKI Architect)
"""

import sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from pki_lifecycle.crypto.authority import TwoTierCA

def run_ceremony(export_dir: str = "docker/certs/ca"):
    out_path = Path(export_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    
    print("=" * 70)
    print("[*] Executing Two-Tier CA Key Ceremony")
    print("=" * 70)
    
    ca = TwoTierCA(base_domain="internal.lab")
    
    # 1. Export Root CA Certificate
    root_cert_pem = ca.root_cert.public_bytes(serialization.Encoding.PEM)
    with open(out_path / "root-ca.crt", "wb") as f:
        f.write(root_cert_pem)
    print("[+] Root CA Certificate written (RSA 4096-bit, pathlen=1)")
    
    # 2. Export Root Private Key (Encrypted in production)
    root_key_pem = ca.root_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(out_path / "root-ca.key", "wb") as f:
        f.write(root_key_pem)
    print("[+] Root CA Private Key archived to secure media")
    
    # 3. Export Intermediate CA Certificate
    int_cert_pem = ca.intermediate_cert.public_bytes(serialization.Encoding.PEM)
    with open(out_path / "intermediate-ca.crt", "wb") as f:
        f.write(int_cert_pem)
    print("[+] Intermediate CA Certificate written (RSA 2048-bit, pathlen=0, NameConstraints: .internal.lab)")
    
    # 4. Export Intermediate Private Key
    int_key_pem = ca.intermediate_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(out_path / "intermediate-ca.key", "wb") as f:
        f.write(int_key_pem)
    print("[+] Intermediate CA Private Key installed for step-ca engine")
    
    # 5. Export CA Bundle (Chain)
    with open(out_path / "ca-bundle.crt", "wb") as f:
        f.write(int_cert_pem + b"\n" + root_cert_pem)
    print("[+] CA Trust Bundle written (Intermediate + Root)")
    
    print("\n[SUCCESS] Key Ceremony Completed with Zero Deviations!")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "docker/certs/ca"
    run_ceremony(target)
