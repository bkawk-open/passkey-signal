#!/bin/bash
set -euo pipefail

# Tear down everything: enclave stack first (depends on main), then main stack.
# Cleans up any retained resources (DynamoDB table, KMS keys).
# Usage: AWS_PROFILE=bkawk ./scripts/destroy-all.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INFRA_DIR="$(dirname "$SCRIPT_DIR")/infra"
REGION=$(aws configure get region 2>/dev/null || echo "us-east-1")

echo "============================================"
echo "  passkey-signal: Full Stack Teardown"
echo "============================================"
echo ""

# --- Step 1: Destroy enclave stack ---

echo "==> Step 1/3: Destroying enclave stack..."

# Revert Lambda env (ignore errors if Lambda is already gone)
echo "    Reverting Lambda to mock mode..."
CURRENT_ENV=$(aws lambda get-function-configuration --function-name passkey-signal-api \
    --query "Environment.Variables" --output json 2>/dev/null || echo "")
if [ -n "$CURRENT_ENV" ] && [ "$CURRENT_ENV" != "" ]; then
    UPDATED_ENV=$(echo "$CURRENT_ENV" | jq '. + {"ENCLAVE_URL": ""}')
    ENV_JSON=$(echo "$UPDATED_ENV" | jq -c '{Variables: .}')
    aws lambda update-function-configuration \
        --function-name passkey-signal-api \
        --environment "$ENV_JSON" \
        --query "FunctionName" --output text 2>/dev/null || true
fi

# Destroy enclave stack (ignore if already gone)
ENCLAVE_STACK=$(aws cloudformation describe-stacks --stack-name PasskeySignalEnclaveStack \
    --query "Stacks[0].StackStatus" --output text 2>/dev/null || echo "GONE")
if [ "$ENCLAVE_STACK" != "GONE" ]; then
    cd "$INFRA_DIR"
    npx cdk destroy PasskeySignalEnclaveStack --force
else
    echo "    Enclave stack already destroyed."
fi

# --- Step 2: Destroy main stack ---

echo ""
echo "==> Step 2/3: Destroying main stack (VPC + Lambda)..."

MAIN_STACK=$(aws cloudformation describe-stacks --stack-name PasskeySignalStack \
    --query "Stacks[0].StackStatus" --output text 2>/dev/null || echo "GONE")
if [ "$MAIN_STACK" != "GONE" ]; then
    cd "$INFRA_DIR"
    npx cdk destroy PasskeySignalStack --force

    # Wait for stack to fully delete (NAT gateway can take 5+ minutes)
    echo "    Waiting for stack deletion to complete..."
    for i in $(seq 1 60); do
        STATUS=$(aws cloudformation describe-stacks --stack-name PasskeySignalStack \
            --query "Stacks[0].StackStatus" --output text 2>/dev/null || echo "DELETED")
        if [ "$STATUS" = "DELETED" ] || [ "$STATUS" = "DELETE_COMPLETE" ]; then
            echo "    Stack deleted."
            break
        fi
        if [ "$STATUS" = "DELETE_FAILED" ]; then
            echo "    WARNING: Stack deletion failed. Check CloudFormation console."
            break
        fi
        printf "."
        sleep 10
    done
else
    echo "    Main stack already destroyed."
fi

# --- Step 3: Clean up retained resources ---

echo ""
echo "==> Step 3/3: Cleaning up retained resources..."

# Delete DynamoDB table if it still exists
TABLE_STATUS=$(aws dynamodb describe-table --table-name passkey-signal \
    --query "Table.TableStatus" --output text 2>/dev/null || echo "GONE")
if [ "$TABLE_STATUS" != "GONE" ]; then
    echo "    Deleting DynamoDB table 'passkey-signal'..."
    aws dynamodb delete-table --table-name passkey-signal --output text 2>/dev/null || true
else
    echo "    DynamoDB table already deleted."
fi

# Schedule KMS key deletion if alias still exists
KEY_ID=$(aws kms describe-key --key-id alias/passkey-signal-enclave-seal \
    --query "KeyMetadata.KeyId" --output text 2>/dev/null || echo "")
if [ -n "$KEY_ID" ]; then
    echo "    Scheduling KMS key $KEY_ID for deletion (7-day waiting period)..."
    aws kms schedule-key-deletion --key-id "$KEY_ID" --pending-window-in-days 7 \
        --output text 2>/dev/null || true
else
    echo "    KMS key already deleted or scheduled."
fi

echo ""
echo "============================================"
echo "  All destroyed. No ongoing charges."
echo "============================================"
