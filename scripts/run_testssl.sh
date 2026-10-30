#!/usr/bin/env bash
# ==============================================================================
# Automated testssl.sh Audit Runner for Group 7 Lab Fleet
# Course: CSSS 441 Software Security I (Project 7: Module 7)
# ==============================================================================
set -euo pipefail

REPORT_DIR="docs/verification/testssl-reports"
mkdir -p "${REPORT_DIR}"

SERVICES=(
    "auth:8443"
    "billing:8444"
    "vault:8445"
    "metrics:8446"
    "portal:8447"
)

echo "======================================================================"
echo "🛡️  Executing testssl.sh Security Audits against Lab Fleet"
echo "======================================================================"

for item in "${SERVICES[@]}"; do
    IFS=":" read -r name port <<< "${item}"
    target="localhost:${port}"
    output_file="${REPORT_DIR}/${name}_testssl_audit.json"

    echo ">>> Scanning ${name} on port ${port}..."

    # Use Docker testssl container with fallback to host binary
    if command -v docker >/dev/null 2>&1; then
        docker run --rm --net=host -v "$(pwd)/${REPORT_DIR}:/data" \
            drwetter/testssl.sh:latest \
            --quiet --color 0 --jsonfile-pretty "/data/${name}_testssl_audit.json" \
            "${target}" || true
    elif command -v testssl.sh >/dev/null 2>&1; then
        testssl.sh --quiet --color 0 --jsonfile-pretty "${output_file}" "${target}" || true
    else
        echo "⚠️ Neither docker nor testssl.sh found locally. Running Python TLS Policy Engine check..."
        python -c "from pki_lifecycle.inventory.collector import inventory_collector; res = inventory_collector.probe_endpoint('localhost', ${port}); print(f'Scan Result for ${name}: Grade {res.get(\"tls_grade\")} | Compliant: {res.get(\"is_compliant\")}')"
    fi
done

echo "✅ Fleet scans complete. Audit reports saved to: ${REPORT_DIR}/"

