# Passkey DKG

Passwordless authentication with **two-party distributed key generation (DKG)** running inside an **AWS Nitro Enclave**. Users authenticate via WebAuthn passkeys and SMS OTP. The system generates a secp256k1 wallet where the private key is split between client and enclave — neither party holds the full key.

## Architecture

```
Browser (WebAuthn + PRF)
    │
    ├── SMS OTP verification
    ├── Passkey registration/login
    └── Client-side DKG (Share A, encrypted with PRF-derived AES key)
         │
    API Gateway ──► Lambda (Go)
         │              │
         │         DynamoDB (sessions, credentials, wallets)
         │
         └──► Nitro Enclave (vsock)
                   │
                   ├── DKG Round 1: key exchange + Schnorr proofs
                   ├── DKG Complete: seal Share B with KMS attestation
                   └── KMS (GenerateDataKey/Decrypt with PCR0 condition)
```

### Key Split

| Share | Location | Protection |
|-------|----------|------------|
| Share A (client) | Encrypted in browser note | AES-256-GCM, key derived from WebAuthn PRF via HKDF with random salt |
| Share B (enclave) | Sealed in DynamoDB | KMS envelope encryption with Nitro attestation (PCR0-bound) |
| Joint public key | Stored plaintext | Additive combination: X = X_A + X_B |

## Project Structure

```
api/                          # Lambda API (Go)
├── main.go                   # Router, CORS, enclave proxy
├── handlers.go               # Auth, OTP, passkey, notes, device enrollment
├── dkg_handlers.go           # Embedded mock DKG (dev fallback)
├── dkg_crypto.go             # Schnorr proofs, secp256k1 operations
├── dynamo.go                 # DynamoDB operations
├── models.go                 # Data models
└── webauthn.go               # WebAuthn configuration

enclave/                      # Nitro Enclave application (Go)
├── main.go                   # HTTP server (vsock or TCP)
├── vsock.go                  # vsock listener
├── Dockerfile                # Multi-stage build for EIF
├── dkg/
│   ├── handlers.go           # DKG round1 + complete handlers
│   ├── crypto.go             # Schnorr proofs, key operations
│   └── types.go              # Session management (bounded map)
└── seal/
    ├── seal.go               # Sealer interface
    ├── kms.go                # KMS sealer with NSM attestation + BER/CMS parsing
    └── mock.go               # Mock sealer (dev mode only)

infra/                        # AWS CDK (TypeScript)
├── lib/
│   ├── passkey-signal-stack.ts          # VPC, Lambda, API Gateway, DynamoDB, CloudFront
│   └── passkey-signal-enclave-stack.ts  # EC2 (Nitro), KMS, S3 deploy bucket, vsock proxies

web/                          # Frontend SPA
├── index.html                # Single-page app shell
├── app.js                    # Auth flows, UI state machine, note encryption
├── dkg.js                    # Client-side DKG (secp256k1, Schnorr, AES-GCM)
└── *.min.js                  # noble-secp256k1, simplewebauthn, qrcode

ios/                          # Native iOS app (Swift)
└── bkawk/
    ├── ContentView.swift     # State machine (enrol → auth → notes)
    ├── Services/             # Secure Enclave, crypto, keychain, API client
    └── Views/                # QR scanner, enrollment, notes, settings

scripts/                      # Deployment automation
├── deploy-all.sh             # Deploy both CDK stacks + build EIF
├── destroy-all.sh            # Tear down everything
├── setup-enclave.sh          # Upload source → SSM build → start enclave → update KMS PCR
├── deploy-enclave.sh         # CDK deploy + setup + Lambda env wiring
├── build-eif.sh              # Build EIF locally, extract PCR values
├── run-enclave.sh            # Start enclave + vsock services
├── stop-enclave.sh           # Stop enclave + vsock services
├── destroy-enclave.sh        # Tear down enclave stack
└── update-kms-policy.sh      # Apply PCR0 attestation to KMS key policy
```

## Security

### Cryptographic

| Feature | Implementation |
|---------|---------------|
| DKG protocol | Two-party additive DKG with Schnorr zero-knowledge proofs (secp256k1) |
| Share A encryption | AES-256-GCM with HKDF-SHA256 key derivation, random 32-byte salt per encryption |
| Share B sealing | KMS GenerateDataKey with Nitro attestation, AES-256-GCM envelope |
| KMS binding | PCR0 attestation condition auto-applied on every EIF build |
| Challenge hashing | Length-prefixed domain-separated SHA-256 (`DKG-POK-v1:`) |
| Key zeroing | Private key bytes zeroed immediately after use |

### Infrastructure

| Feature | Implementation |
|---------|---------------|
| Enclave isolation | AWS Nitro Enclave (vsock only, no network, no persistent storage) |
| Enclave startup guard | Refuses MockSealer in production (vsock mode requires NSM device) |
| Session limits | Max 1000 concurrent DKG sessions, 10-minute TTL, UUID format validation |
| Network | Lambda in private VPC subnets, enclave reachable only via Lambda security group |
| Auth tokens | SHA-256 hashed, TTL-bound, single-use OTP with constant-time comparison |
| Rate limiting | 5 OTP requests/phone/hour, API Gateway throttle (100 req/s) |
| Error messages | Normalized responses prevent state enumeration |
| Input validation | UUID session IDs, device name sanitization (printable ASCII only) |
| CORS | Explicit origin allowlist |

## Deploy

### Full deployment (from scratch)

```bash
AWS_PROFILE=bkawk ./scripts/deploy-all.sh
```

### Enclave only (rebuild after code changes)

```bash
AWS_PROFILE=bkawk ./scripts/setup-enclave.sh
```

This uploads source to S3, builds Docker + EIF on EC2 via SSM, starts the enclave, and updates the KMS key policy with the new PCR0 value.

### Tear down

```bash
AWS_PROFILE=bkawk ./scripts/destroy-all.sh
```

## Environment

- **Region**: us-east-1
- **Web**: `https://passkey-signal.bkawk.com`
- **API**: `https://api.passkey-signal.bkawk.com`
- **Stacks**: `PasskeySignalStack`, `PasskeySignalEnclaveStack`

## Requirements

- AWS account with Nitro Enclave support (m5.xlarge or similar)
- Node.js 18+ and AWS CDK CLI
- Go 1.25+
- Docker (for EIF builds on EC2)
- iOS 17+ / iPhone with Face ID (for mobile app)
