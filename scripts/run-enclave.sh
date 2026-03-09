#!/bin/bash
set -euo pipefail

# Start the enclave and enable the vsock proxy service.
# The socat proxy runs as a systemd service (auto-restarts on failure).
# Usage: sudo ./scripts/run-enclave.sh [/path/to/enclave.eif]

EIF_PATH="${1:-/opt/enclave.eif}"

if [ ! -f "$EIF_PATH" ]; then
    echo "ERROR: EIF not found at $EIF_PATH"
    echo "Build it first: ./scripts/build-eif.sh"
    exit 1
fi

# Stop vsock proxy services first — they conflict with enclave startup
echo "Stopping vsock services..."
systemctl stop kms-proxy cred-proxy enclave-proxy 2>/dev/null || true

# Stop any existing enclave
EXISTING=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID // empty')
if [ -n "$EXISTING" ]; then
    echo "Stopping existing enclave $EXISTING..."
    nitro-cli terminate-enclave --enclave-id "$EXISTING"
fi

echo "Starting enclave..."
ENCLAVE_ID=$(nitro-cli run-enclave \
    --eif-path "$EIF_PATH" \
    --cpu-count 2 \
    --memory 4096 \
    --enclave-cid 16 \
    | jq -r '.EnclaveID')

echo "Enclave started: $ENCLAVE_ID"
echo "Enclave CID: 16, Port: 5000"

# Start all vsock services now that the enclave is running
echo "Starting vsock services..."
systemctl start enclave-proxy kms-proxy cred-proxy

# Verify
sleep 2
for svc in enclave-proxy kms-proxy cred-proxy; do
    if systemctl is-active --quiet "$svc"; then
        echo "  $svc: running"
    else
        echo "  WARNING: $svc failed to start"
    fi
done

echo ""
echo "Enclave is ready. Health check:"
curl -s http://localhost:8443/health || echo "(health check failed - enclave may need a moment)"
