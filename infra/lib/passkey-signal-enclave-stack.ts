import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';

export interface PasskeySignalEnclaveStackProps extends cdk.StackProps {
  vpc: ec2.IVpc;
  lambdaSecurityGroup: ec2.ISecurityGroup;
}

export class PasskeySignalEnclaveStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: PasskeySignalEnclaveStackProps) {
    super(scope, id, props);

    const { vpc, lambdaSecurityGroup } = props;

    // --- Elastic IP (stable address survives reboots) ---

    const eip = new ec2.CfnEIP(this, 'EnclaveEip', {
      tags: [{ key: 'Name', value: 'passkey-signal-enclave' }],
    });

    // --- Security Group (locked down) ---

    const enclaveSg = new ec2.SecurityGroup(this, 'EnclaveSG', {
      vpc,
      description: 'Enclave EC2 - inbound only from Lambda SG',
      allowAllOutbound: true,
    });

    // Only Lambda can reach the enclave proxy — no public access, no SSH
    enclaveSg.addIngressRule(
      lambdaSecurityGroup,
      ec2.Port.tcp(8443),
      'Enclave proxy from Lambda',
    );

    // --- KMS Key for sealing Share B ---
    // The key policy allows the enclave EC2 role to Encrypt/Decrypt.
    // In production, add PCR attestation conditions after building the EIF:
    //   "Condition": { "StringEqualsIgnoreCase": {
    //     "kms:RecipientAttestation:PCR0": "<pcr0-value>"
    //   }}
    // Use scripts/update-kms-policy.sh to apply PCR values after each EIF rebuild.

    const sealingKey = new kms.Key(this, 'SealingKey', {
      alias: 'passkey-signal-enclave-seal',
      description: 'Seals DKG Share B inside Nitro Enclave',
      enableKeyRotation: true,
    });

    // --- Deployment Bucket (for uploading enclave source to EC2) ---

    const deployBucket = new s3.Bucket(this, 'DeployBucket', {
      bucketName: `passkey-signal-enclave-deploy-${this.account}`,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      lifecycleRules: [{ expiration: cdk.Duration.days(1) }],
    });

    // --- IAM Role ---

    const role = new iam.Role(this, 'EnclaveRole', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
      ],
    });

    // KMS permissions for the enclave to seal/unseal keys
    sealingKey.grant(role, 'kms:Encrypt', 'kms:Decrypt', 'kms:GenerateDataKey');

    // S3 read access for deployment artifacts
    deployBucket.grantRead(role);

    // Allow the instance to write its private IP to SSM
    role.addToPolicy(new iam.PolicyStatement({
      actions: ['ssm:PutParameter', 'ssm:DeleteParameter'],
      resources: [`arn:aws:ssm:${this.region}:${this.account}:parameter/passkey-signal/enclave-url`],
    }));

    // --- EC2 Instance ---

    const userData = ec2.UserData.forLinux();
    userData.addCommands(
      '#!/bin/bash',
      'set -euo pipefail',
      'exec > >(tee /var/log/enclave-setup.log) 2>&1',

      // Install Nitro Enclaves CLI, socat, docker
      'dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel socat jq docker',
      'systemctl enable --now nitro-enclaves-allocator',
      'systemctl enable --now docker',
      'usermod -aG ne ec2-user',
      'usermod -aG docker ec2-user',

      // Configure enclave allocator (2 vCPUs, 4GB RAM)
      'sed -i "s/^memory_mib:.*/memory_mib: 4096/" /etc/nitro_enclaves/allocator.yaml',
      'sed -i "s/^cpu_count:.*/cpu_count: 2/" /etc/nitro_enclaves/allocator.yaml',
      'systemctl restart nitro-enclaves-allocator',

      // Write private IP to SSM (Lambda uses private IP within the shared VPC)
      'TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")',
      'PRIVATE_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)',
      `aws ssm put-parameter --name "/passkey-signal/enclave-url" --value "http://\${PRIVATE_IP}:8443" --type String --overwrite --region ${this.region}`,

      // --- Systemd service: vsock proxy (socat) ---
      // Forwards TCP 8443 on host to vsock CID 16, port 5000 inside enclave
      'cat > /etc/systemd/system/enclave-proxy.service << \'UNIT\'',
      '[Unit]',
      'Description=Enclave vsock proxy (TCP 8443 -> vsock 16:5000)',
      'After=network.target',
      '',
      '[Service]',
      'Type=simple',
      'ExecStart=/usr/bin/socat TCP-LISTEN:8443,fork,reuseaddr VSOCK-CONNECT:16:5000',
      'Restart=always',
      'RestartSec=3',
      '',
      '[Install]',
      'WantedBy=multi-user.target',
      'UNIT',
      'systemctl daemon-reload',
      'systemctl enable enclave-proxy',

      // --- Systemd service: vsock proxy for KMS ---
      // Forwards vsock port 8000 to KMS endpoint (for enclave attestation-based sealing)
      `cat > /etc/systemd/system/kms-proxy.service << UNIT`,
      '[Unit]',
      'Description=KMS vsock proxy for Nitro Enclave',
      'After=network.target',
      '',
      '[Service]',
      'Type=simple',
      `ExecStart=/usr/bin/vsock-proxy 8000 kms.${this.region}.amazonaws.com 443`,
      'Restart=always',
      'RestartSec=3',
      '',
      '[Install]',
      'WantedBy=multi-user.target',
      'UNIT',
      'systemctl daemon-reload',
      // Do NOT enable/start kms-proxy at boot — it conflicts with enclave startup.
      // It will be started by run-enclave.sh after the enclave is running.

      // --- Credential proxy for enclave (IMDS over vsock) ---
      // The enclave cannot reach IMDS directly. This Python script listens
      // on vsock port 9000 and returns IAM role credentials from IMDS.
      `cat > /usr/local/bin/cred-proxy.py << 'CREDPY'`,
      '#!/usr/bin/env python3',
      'import socket, subprocess, json, sys, os',
      '',
      'VSOCK_PORT = 9000',
      '',
      'def fetch_creds():',
      '    import urllib.request',
      '    token_req = urllib.request.Request(',
      '        "http://169.254.169.254/latest/api/token",',
      '        method="PUT",',
      '        headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"}',
      '    )',
      '    token = urllib.request.urlopen(token_req, timeout=5).read().decode()',
      '    headers = {"X-aws-ec2-metadata-token": token}',
      '    role_req = urllib.request.Request(',
      '        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",',
      '        headers=headers',
      '    )',
      '    role = urllib.request.urlopen(role_req, timeout=5).read().decode().strip()',
      '    cred_req = urllib.request.Request(',
      '        f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}",',
      '        headers=headers',
      '    )',
      '    return urllib.request.urlopen(cred_req, timeout=5).read()',
      '',
      'sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)',
      'sock.bind((socket.VMADDR_CID_ANY, VSOCK_PORT))',
      'sock.listen(4)',
      'print(f"Credential proxy listening on vsock port {VSOCK_PORT}", flush=True)',
      '',
      'while True:',
      '    conn, addr = sock.accept()',
      '    try:',
      '        data = fetch_creds()',
      '        conn.sendall(data)',
      '    except Exception as e:',
      '        err = json.dumps({"error": str(e)}).encode()',
      '        conn.sendall(err)',
      '    finally:',
      '        conn.close()',
      'CREDPY',
      'chmod +x /usr/local/bin/cred-proxy.py',

      // Systemd service for credential proxy
      'cat > /etc/systemd/system/cred-proxy.service << \'UNIT\'',
      '[Unit]',
      'Description=IMDS credential proxy for Nitro Enclave (vsock 9000)',
      'After=network.target',
      '',
      '[Service]',
      'Type=simple',
      'ExecStart=/usr/bin/python3 /usr/local/bin/cred-proxy.py',
      'Restart=always',
      'RestartSec=3',
      '',
      '[Install]',
      'WantedBy=multi-user.target',
      'UNIT',
      'systemctl daemon-reload',
      // Do NOT enable/start cred-proxy at boot — it conflicts with enclave startup.
      // It will be started by run-enclave.sh after the enclave is running.

      // Log completion
      'echo "Enclave host ready. Upload EIF, then run: sudo ./scripts/run-enclave.sh"',
    );

    const keyPair = ec2.KeyPair.fromKeyPairName(this, 'KeyPair', 'passkey-signal');

    const instance = new ec2.Instance(this, 'EnclaveHost', {
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.XLARGE),
      machineImage: ec2.MachineImage.latestAmazonLinux2023(),
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
      securityGroup: enclaveSg,
      role,
      userData,
      keyPair,
      blockDevices: [
        {
          deviceName: '/dev/xvda',
          volume: ec2.BlockDeviceVolume.ebs(30, {
            encrypted: true,
          }),
        },
      ],
    });

    // Enable Nitro Enclaves on the instance
    (instance.node.defaultChild as ec2.CfnInstance).addPropertyOverride(
      'EnclaveOptions.Enabled',
      true,
    );

    // Associate Elastic IP with instance
    new ec2.CfnEIPAssociation(this, 'EipAssoc', {
      allocationId: eip.attrAllocationId,
      instanceId: instance.instanceId,
    });

    // --- SSM Parameter (stores the enclave private IP for Lambda) ---

    new ssm.StringParameter(this, 'EnclaveUrlParam', {
      parameterName: '/passkey-signal/enclave-url',
      stringValue: `http://${instance.instancePrivateIp}:8443`,
      description: 'Enclave proxy URL for Lambda DKG routing (private IP within shared VPC)',
    });

    // --- Outputs ---

    new cdk.CfnOutput(this, 'InstanceId', {
      value: instance.instanceId,
    });

    new cdk.CfnOutput(this, 'PrivateIp', {
      value: instance.instancePrivateIp,
    });

    new cdk.CfnOutput(this, 'ElasticIp', {
      value: eip.ref,
    });

    new cdk.CfnOutput(this, 'EnclaveUrl', {
      value: `http://${instance.instancePrivateIp}:8443`,
    });

    new cdk.CfnOutput(this, 'SsmConnect', {
      value: `aws ssm start-session --target ${instance.instanceId}`,
    });

    new cdk.CfnOutput(this, 'KmsKeyArn', {
      value: sealingKey.keyArn,
    });

    new cdk.CfnOutput(this, 'DeployBucketName', {
      value: deployBucket.bucketName,
    });
  }
}
