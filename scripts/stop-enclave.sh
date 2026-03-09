#!/bin/bash
set -euo pipefail

# Stop the enclave and vsock proxy service.
# Usage: sudo ./scripts/stop-enclave.sh

echo "Stopping vsock proxy service..."
systemctl stop enclave-proxy 2>/dev/null || true

echo "Terminating enclave..."
ENCLAVE_ID=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID // empty')
if [ -n "$ENCLAVE_ID" ]; then
    nitro-cli terminate-enclave --enclave-id "$ENCLAVE_ID"
    echo "Enclave $ENCLAVE_ID terminated"
else
    echo "No running enclave found"
fi
