#!/bin/bash
set -euo pipefail

# Update the KMS key policy with the current PCR values from pcr-values.json.
# Run this after each EIF rebuild to lock the KMS key to the new enclave image.
# Usage: AWS_PROFILE=bkawk ./scripts/update-kms-policy.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PCR_FILE="$PROJECT_DIR/enclave/pcr-values.json"

if [ ! -f "$PCR_FILE" ]; then
    echo "ERROR: $PCR_FILE not found. Run build-eif.sh first."
    exit 1
fi

PCR0=$(jq -r '.PCR0' "$PCR_FILE")
if [ -z "$PCR0" ] || [ "$PCR0" = "null" ]; then
    echo "ERROR: PCR0 not found in $PCR_FILE"
    exit 1
fi

echo "PCR0: $PCR0"

# Get the KMS key alias
KEY_ID=$(aws kms describe-key --key-id alias/passkey-signal-enclave-seal --query "KeyMetadata.KeyId" --output text 2>/dev/null || echo "")

if [ -z "$KEY_ID" ]; then
    echo "ERROR: KMS key alias/passkey-signal-enclave-seal not found."
    echo "Deploy the enclave stack first."
    exit 1
fi

echo "KMS Key ID: $KEY_ID"

ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
REGION=$(aws configure get region 2>/dev/null || echo "us-east-1")

# Build the key policy with PCR attestation condition
POLICY=$(cat <<POLICY
{
  "Version": "2012-10-17",
  "Id": "enclave-seal-policy",
  "Statement": [
    {
      "Sid": "RootAccess",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::${ACCOUNT_ID}:root"},
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "EnclaveAttestationSeal",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::${ACCOUNT_ID}:root"},
      "Action": ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"],
      "Resource": "*",
      "Condition": {
        "StringEqualsIgnoreCase": {
          "kms:RecipientAttestation:PCR0": "${PCR0}"
        }
      }
    }
  ]
}
POLICY
)

echo ""
echo "==> Updating KMS key policy with PCR0 attestation condition..."
aws kms put-key-policy \
    --key-id "$KEY_ID" \
    --policy-name default \
    --policy "$POLICY"

echo "==> Done! KMS key now requires PCR0: ${PCR0:0:32}..."
