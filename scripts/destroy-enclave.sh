#!/bin/bash
set -euo pipefail

# Tear down the Nitro Enclave stack and revert Lambda to mock mode.
# Usage: AWS_PROFILE=bkawk ./scripts/destroy-enclave.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INFRA_DIR="$(dirname "$SCRIPT_DIR")/infra"

echo "==> Reverting Lambda to mock mode..."
CURRENT_ENV=$(aws lambda get-function-configuration --function-name passkey-signal-api --query "Environment.Variables" --output json)
UPDATED_ENV=$(echo "$CURRENT_ENV" | jq '. + {"ENCLAVE_URL": ""}')
ENV_JSON=$(echo "$UPDATED_ENV" | jq -c '{Variables: .}')
aws lambda update-function-configuration \
    --function-name passkey-signal-api \
    --environment "$ENV_JSON" \
    --query "FunctionName" --output text

echo ""
echo "==> Destroying enclave stack..."
cd "$INFRA_DIR"
npx cdk destroy PasskeySignalEnclaveStack --force

echo ""
echo "==> Done! Lambda is back to using the embedded mock DKG."
