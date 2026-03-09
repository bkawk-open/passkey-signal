#!/bin/bash
set -euo pipefail

# Deploy everything from scratch: main stack + enclave stack + EIF build.
# Single command: AWS_PROFILE=bkawk ./scripts/deploy-all.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INFRA_DIR="$(dirname "$SCRIPT_DIR")/infra"

echo "============================================"
echo "  passkey-signal: Full Stack Deploy"
echo "============================================"
echo ""

echo "==> Step 1/3: Deploying main stack (VPC, Lambda, DynamoDB, CloudFront)..."
cd "$INFRA_DIR"
npx cdk deploy PasskeySignalStack --require-approval never

echo ""
echo "==> Step 2/3: Deploying enclave stack (EC2, KMS, S3)..."
npx cdk deploy PasskeySignalEnclaveStack --require-approval never

echo ""
echo "==> Step 3/3: Building EIF, starting enclave, wiring Lambda..."
"$SCRIPT_DIR/setup-enclave.sh"

# Wire Lambda to enclave
echo ""
echo "==> Updating Lambda ENCLAVE_URL..."
ENCLAVE_URL=$(aws ssm get-parameter --name "/passkey-signal/enclave-url" \
    --query "Parameter.Value" --output text 2>/dev/null || echo "")

if [ -z "$ENCLAVE_URL" ]; then
    echo "WARNING: SSM parameter /passkey-signal/enclave-url not found."
    echo "Lambda will use embedded mock DKG."
else
    CURRENT_ENV=$(aws lambda get-function-configuration --function-name passkey-signal-api \
        --query "Environment.Variables" --output json)
    UPDATED_ENV=$(echo "$CURRENT_ENV" | jq --arg url "$ENCLAVE_URL" '. + {"ENCLAVE_URL": $url}')
    ENV_JSON=$(echo "$UPDATED_ENV" | jq -c '{Variables: .}')
    aws lambda update-function-configuration \
        --function-name passkey-signal-api \
        --environment "$ENV_JSON" \
        --query "FunctionName" --output text
    echo "    Lambda wired to enclave at $ENCLAVE_URL"
fi

echo ""
echo "============================================"
echo "  All deployed! Enclave is running."
echo ""
echo "  Web:  https://passkey-signal.bkawk.com"
echo "  API:  https://api.passkey-signal.bkawk.com"
echo "============================================"
