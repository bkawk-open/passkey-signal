#!/bin/bash
set -euo pipefail

# Deploy everything from scratch: main stack + enclave stack + EIF build.
# Single command: AWS_PROFILE=bkawk ./scripts/deploy-all.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INFRA_DIR="$(dirname "$SCRIPT_DIR")/infra"
REGION="us-east-1"
KEY_PAIR_NAME="passkey-signal"

echo "============================================"
echo "  passkey-signal: Full Stack Deploy"
echo "============================================"
echo ""

# -- Pre-flight checks --

echo "==> Pre-flight checks..."

# Ensure EC2 key pair exists
if ! aws ec2 describe-key-pairs --key-names "$KEY_PAIR_NAME" --region "$REGION" >/dev/null 2>&1; then
    echo "    Creating EC2 key pair '$KEY_PAIR_NAME'..."
    aws ec2 create-key-pair --key-name "$KEY_PAIR_NAME" --key-type ed25519 --region "$REGION" \
        --query "KeyMaterial" --output text > "/tmp/${KEY_PAIR_NAME}.pem"
    chmod 600 "/tmp/${KEY_PAIR_NAME}.pem"
    echo "    Key pair created. Private key saved to /tmp/${KEY_PAIR_NAME}.pem"
else
    echo "    EC2 key pair '$KEY_PAIR_NAME' exists."
fi

# Clean up any ROLLBACK_COMPLETE enclave stack
STACK_STATUS=$(aws cloudformation describe-stacks --stack-name PasskeySignalEnclaveStack --region "$REGION" \
    --query "Stacks[0].StackStatus" --output text 2>/dev/null || echo "DOES_NOT_EXIST")
if [ "$STACK_STATUS" = "ROLLBACK_COMPLETE" ]; then
    echo "    Deleting failed enclave stack (ROLLBACK_COMPLETE)..."
    aws cloudformation delete-stack --stack-name PasskeySignalEnclaveStack --region "$REGION"
    aws cloudformation wait stack-delete-complete --stack-name PasskeySignalEnclaveStack --region "$REGION"
    echo "    Deleted."
fi

echo "    Pre-flight OK."
echo ""

# -- Step 1: Main stack --

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
