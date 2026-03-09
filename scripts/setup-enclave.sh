#!/bin/bash
set -euo pipefail

# Upload enclave source to S3, then build and run the EIF on EC2 via SSM.
# This is the single command to go from "CDK deployed" to "enclave running".
# Usage: AWS_PROFILE=bkawk ./scripts/setup-enclave.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
REGION=$(aws configure get region 2>/dev/null || echo "us-east-1")
ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)

BUCKET="passkey-signal-enclave-deploy-${ACCOUNT_ID}"

# --- Get instance ID from CloudFormation ---

echo "==> Looking up enclave instance..."
INSTANCE_ID=$(aws cloudformation describe-stacks \
    --stack-name PasskeySignalEnclaveStack \
    --query "Stacks[0].Outputs[?OutputKey=='InstanceId'].OutputValue" \
    --output text 2>/dev/null || echo "")

if [ -z "$INSTANCE_ID" ]; then
    echo "ERROR: Could not find enclave instance. Deploy the enclave stack first:"
    echo "  AWS_PROFILE=bkawk ./scripts/deploy-enclave.sh"
    exit 1
fi

echo "Instance: $INSTANCE_ID"

# --- Wait for instance to be running and SSM-ready ---

echo "==> Waiting for instance to be running..."
aws ec2 wait instance-running --instance-ids "$INSTANCE_ID"

echo "==> Waiting for SSM agent (this can take 2-3 minutes on first boot)..."
for i in $(seq 1 30); do
    SSM_STATUS=$(aws ssm describe-instance-information \
        --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
        --query "InstanceInformationList[0].PingStatus" \
        --output text 2>/dev/null || echo "None")
    if [ "$SSM_STATUS" = "Online" ]; then
        echo "SSM agent online."
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: SSM agent not ready after 5 minutes. Check instance status."
        exit 1
    fi
    printf "."
    sleep 10
done

# --- Package and upload enclave source ---

echo "==> Packaging enclave source..."
TARBALL="/tmp/enclave-source.tar.gz"
tar -czf "$TARBALL" -C "$PROJECT_DIR" \
    enclave/main.go enclave/vsock.go enclave/go.mod enclave/go.sum \
    enclave/Dockerfile enclave/frost/ enclave/seal/ \
    scripts/build-eif.sh scripts/run-enclave.sh scripts/stop-enclave.sh

echo "==> Uploading to s3://${BUCKET}/enclave-source.tar.gz..."
aws s3 cp "$TARBALL" "s3://${BUCKET}/enclave-source.tar.gz"
rm -f "$TARBALL"

# --- Run remote build via SSM ---

echo "==> Running remote build and start on $INSTANCE_ID..."
COMMAND_ID=$(aws ssm send-command \
    --instance-ids "$INSTANCE_ID" \
    --document-name "AWS-RunShellScript" \
    --timeout-seconds 600 \
    --parameters "commands=[
        'set -euo pipefail',
        'export HOME=/root',
        'exec > >(tee /var/log/enclave-deploy.log) 2>&1',
        'echo \"==> Downloading enclave source...\"',
        'mkdir -p /opt/passkey-signal',
        'cd /opt/passkey-signal',
        'aws s3 cp s3://${BUCKET}/enclave-source.tar.gz /tmp/enclave-source.tar.gz',
        'tar -xzf /tmp/enclave-source.tar.gz',
        'rm -f /tmp/enclave-source.tar.gz',
        'echo \"==> Waiting for Docker to be ready...\"',
        'for i in \$(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 5; done',
        'echo \"==> Building Docker image...\"',
        'docker build -t passkey-signal-enclave enclave/',
        'echo \"==> Building EIF...\"',
        'nitro-cli build-enclave --docker-uri passkey-signal-enclave:latest --output-file /opt/enclave.eif 2>&1 | tee /tmp/eif-build.json',
        'echo \"==> Stopping vsock services and any existing enclave...\"',
        'systemctl stop kms-proxy cred-proxy enclave-proxy 2>/dev/null || true',
        'EXISTING=\$(nitro-cli describe-enclaves | jq -r \".[0].EnclaveID // empty\")',
        'if [ -n \"\$EXISTING\" ]; then nitro-cli terminate-enclave --enclave-id \"\$EXISTING\"; fi',
        'sleep 2',
        'echo \"==> Starting enclave...\"',
        'nitro-cli run-enclave --eif-path /opt/enclave.eif --cpu-count 2 --memory 4096 --enclave-cid 16',
        'echo \"==> Starting vsock services...\"',
        'systemctl start enclave-proxy kms-proxy cred-proxy',
        'sleep 3',
        'echo \"==> Health check...\"',
        'curl -sf http://localhost:8443/health && echo \" OK\" || echo \" FAILED\"',
        'echo \"==> Done!\"'
    ]" \
    --query "Command.CommandId" \
    --output text)

echo "SSM Command ID: $COMMAND_ID"
echo ""
echo "==> Waiting for remote build to complete (this takes 2-5 minutes)..."

# Poll for completion
while true; do
    STATUS=$(aws ssm get-command-invocation \
        --command-id "$COMMAND_ID" \
        --instance-id "$INSTANCE_ID" \
        --query "Status" \
        --output text 2>/dev/null || echo "Pending")

    case "$STATUS" in
        Success)
            echo ""
            echo "==> Remote build succeeded!"
            echo ""
            # Show the output
            aws ssm get-command-invocation \
                --command-id "$COMMAND_ID" \
                --instance-id "$INSTANCE_ID" \
                --query "StandardOutputContent" \
                --output text
            break
            ;;
        Failed|TimedOut|Cancelled)
            echo ""
            echo "ERROR: Remote build $STATUS"
            echo ""
            echo "--- stdout ---"
            aws ssm get-command-invocation \
                --command-id "$COMMAND_ID" \
                --instance-id "$INSTANCE_ID" \
                --query "StandardOutputContent" \
                --output text
            echo ""
            echo "--- stderr ---"
            aws ssm get-command-invocation \
                --command-id "$COMMAND_ID" \
                --instance-id "$INSTANCE_ID" \
                --query "StandardErrorContent" \
                --output text
            exit 1
            ;;
        *)
            printf "."
            sleep 10
            ;;
    esac
done

# --- Extract PCR0 from build output and update KMS policy ---

BUILD_OUTPUT=$(aws ssm get-command-invocation \
    --command-id "$COMMAND_ID" \
    --instance-id "$INSTANCE_ID" \
    --query "StandardOutputContent" \
    --output text)

PCR0=$(echo "$BUILD_OUTPUT" | grep -o '"PCR0": "[^"]*"' | head -1 | cut -d'"' -f4)

if [ -n "$PCR0" ] && [ ${#PCR0} -eq 96 ]; then
    echo ""
    echo "==> Updating KMS key policy with PCR0 attestation..."
    echo "    PCR0: ${PCR0:0:32}..."

    KEY_ID=$(aws kms describe-key --key-id alias/passkey-signal-enclave-seal \
        --query "KeyMetadata.KeyId" --output text 2>/dev/null || echo "")

    if [ -n "$KEY_ID" ]; then
        POLICY=$(cat <<KMSPOLICY
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
KMSPOLICY
)
        aws kms put-key-policy --key-id "$KEY_ID" --policy-name default --policy "$POLICY"
        echo "    KMS policy updated with PCR0 attestation."
    else
        echo "    WARNING: KMS key not found, skipping PCR policy update."
    fi
else
    echo ""
    echo "    WARNING: Could not extract PCR0 from build output, skipping KMS policy update."
fi

echo ""
echo "==> Enclave is running. Lambda should be able to reach it via private IP."
echo "    SSM into instance: aws ssm start-session --target $INSTANCE_ID"
