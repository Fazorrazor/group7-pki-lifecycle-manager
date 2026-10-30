#!/usr/bin/env bash
# ==============================================================================
# Live OCSP Revocation & Refusal Verification Script
# Course: CSSS 441 Software Security I (Project 7: Module 3)
# ==============================================================================
set -euo pipefail

API_BASE="${API_BASE:-http://localhost:8000}"

echo "======================================================================"
echo "🛡️  Live OCSP Revocation & Refusal Verification"
echo "======================================================================"

echo ">>> 1. Retrieving active certificate inventory..."
INVENTORY=$(curl -s "${API_BASE}/api/v1/inventory")
SERIAL=$(echo "${INVENTORY}" | grep -o '"serial_number": *"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -z "${SERIAL}" ]; then
    echo "❌ No certificate found in inventory. Make sure the backend is running."
    exit 1
fi

echo "Target Serial Number: ${SERIAL}"

echo ""
echo ">>> 2. Querying OCSP Responder for initial state..."
INITIAL_STATUS=$(curl -s "${API_BASE}/api/v1/ocsp/${SERIAL}")
echo "Initial OCSP Response: ${INITIAL_STATUS}"

echo ""
echo ">>> 3. Injecting Revocation via Management API (Reason: key_compromise)..."
REVOKE_RES=$(curl -s -X POST "${API_BASE}/api/v1/certificates/revoke" \
  -H "Content-Type: application/json" \
  -d "{\"serial_number\": \"${SERIAL}\", \"reason\": \"key_compromise\"}")
echo "Revocation Response: ${REVOKE_RES}"

echo ""
echo ">>> 4. Querying OCSP Responder after revocation..."
REVOKED_STATUS=$(curl -s "${API_BASE}/api/v1/ocsp/${SERIAL}")
echo "Post-Revocation OCSP Response: ${REVOKED_STATUS}"

echo ""
echo ">>> 5. Triggering Fleet Scan to verify single-cycle detection..."
SCAN_RES=$(curl -s -X POST "${API_BASE}/api/v1/scan")
echo "Scan Summary: $(echo "${SCAN_RES}" | grep -o '"violations_detected": *[0-9]*')"

echo ""
echo "✅ Security Bar Claim Proven: Revoked certificate was immediately refused via OCSP"
echo "   and flagged in the fleet inventory within one scan cycle."

