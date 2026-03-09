#!/bin/bash
set -euo pipefail

# Full enclave deployment: CDK stack + remote EIF build + Lambda wiring.
# This is the one command to go from nothing to a running enclave.
# Usage: AWS_PROFILE=bkawk ./scripts/deploy-enclave.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INFRA_DIR="$(dirname "$SCRIPT_DIR")/infra"

echo "==> Deploying enclave stack..."
cd "$INFRA_DIR"
npx cdk deploy PasskeySignalEnclaveStack --require-approval never

echo ""
echo "==> Building and starting enclave on EC2..."
"$SCRIPT_DIR/setup-enclave.sh"

echo ""
echo "==> Getting enclave URL from SSM..."
ENCLAVE_URL=$(aws ssm get-parameter --name "/passkey-signal/enclave-url" --query "Parameter.Value" --output text 2>/dev/null || echo "")

if [ -z "$ENCLAVE_URL" ]; then
    echo "ERROR: SSM parameter /passkey-signal/enclave-url not found"
    exit 1
fi

echo "Enclave URL (private): $ENCLAVE_URL"

echo ""
echo "==> Updating Lambda to use enclave..."
CURRENT_ENV=$(aws lambda get-function-configuration --function-name passkey-signal-api --query "Environment.Variables" --output json)
UPDATED_ENV=$(echo "$CURRENT_ENV" | jq --arg url "$ENCLAVE_URL" '. + {"ENCLAVE_URL": $url}')
ENV_JSON=$(echo "$UPDATED_ENV" | jq -c '{Variables: .}')
aws lambda update-function-configuration \
    --function-name passkey-signal-api \
    --environment "$ENV_JSON" \
    --query "FunctionName" --output text

echo ""
echo "==> Done! Full enclave deployment complete."
echo "    Lambda is now routing DKG to the enclave via private IP."
