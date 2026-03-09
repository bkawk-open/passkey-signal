#!/bin/bash
set -euo pipefail

# Build the enclave EIF image and record PCR values.
# Must be run on an EC2 instance with nitro-cli installed.
# Usage: ./scripts/build-eif.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ENCLAVE_DIR="$PROJECT_DIR/enclave"
PCR_FILE="$ENCLAVE_DIR/pcr-values.json"

echo "Building Docker image..."
docker build -t passkey-signal-enclave "$ENCLAVE_DIR"

echo "Building enclave image (EIF)..."
BUILD_OUTPUT=$(nitro-cli build-enclave \
    --docker-uri passkey-signal-enclave:latest \
    --output-file "$PROJECT_DIR/enclave.eif" 2>&1)

echo "$BUILD_OUTPUT"

# Extract PCR values and save to file
PCR0=$(echo "$BUILD_OUTPUT" | jq -r '.Measurements.PCR0')
PCR1=$(echo "$BUILD_OUTPUT" | jq -r '.Measurements.PCR1')
PCR2=$(echo "$BUILD_OUTPUT" | jq -r '.Measurements.PCR2')
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

cat > "$PCR_FILE" <<EOF
{
  "build": "$BUILD_TIME",
  "PCR0": "$PCR0",
  "PCR1": "$PCR1",
  "PCR2": "$PCR2",
  "note": "PCR values change with every code change. Update this file after each enclave rebuild."
}
EOF

echo ""
echo "EIF built at: $PROJECT_DIR/enclave.eif"
echo "PCR values saved to: $PCR_FILE"
