# Passkey Signal

Passwordless authentication with **FROST threshold signing** (2-of-2) inside an **AWS Nitro Enclave** and **Signal Protocol key infrastructure** for future end-to-end encrypted messaging. Users authenticate via WebAuthn passkeys and SMS OTP. The system generates a secp256k1 wallet where the private key is **never reconstructed** — each party computes a partial signature and the enclave aggregates.

## Architecture

```
Browser (WebAuthn + PRF)
    │
    ├── SMS OTP verification
    ├── Passkey registration/login
    ├── FROST DKG via WebAssembly (client signing share)
    └── Signal key generation (per-credential Ed25519/X25519)
         │
    API Gateway ──► Lambda (Go)
         │              │
         │         DynamoDB (sessions, credentials, wallets, Signal keys)
         │
         └──► Nitro Enclave (vsock)
                   │
                   ├── FROST DKG Round 1: commitment + polynomial exchange
                   ├── FROST DKG Round 2: share verification + sealing
                   └── KMS (GenerateDataKey/Decrypt with PCR0 condition)

iOS App (Swift)
    │
    ├── QR-based device enrollment
    ├── Secure Enclave key generation (P-256 ECDH + signing)
    ├── Face ID biometric auth
    └── Signal key generation (CryptoKit Curve25519)
```

### FROST Threshold Signing (2-of-2)

| Component | Location | Protection |
|-----------|----------|------------|
| Client signing share | Encrypted in browser | AES-256-GCM, key derived from WebAuthn PRF via HKDF |
| Enclave signing share | Sealed in DynamoDB | KMS envelope encryption with Nitro attestation (PCR0-bound) |
| Group public key | Stored plaintext | Derived from FROST DKG commitments: Y = C₁[0] + C₂[0] |

The full private key never exists in memory on either side. During signing, each party produces a partial Schnorr signature; the enclave aggregates them into a standard signature verifiable with the group public key.

### Signal Protocol Keys (per credential)

Each passkey/device gets its own Signal key set for future E2E messaging:

| Key Type | Algorithm | Purpose |
|----------|-----------|---------|
| Identity key | Ed25519 | Long-term device identity |
| Signed PreKey | X25519 | Medium-term key agreement, signed by identity key |
| One-Time PreKeys | X25519 (×20) | Single-use keys for X3DH session establishment |

Web passkeys derive identity keys deterministically from PRF output + credential ID via HKDF. iOS devices generate random CryptoKit keys stored in the Keychain.

## Project Structure

```
api/                          # Lambda API (Go)
├── main.go                   # Router, CORS, enclave proxy
├── handlers.go               # Auth, OTP, passkey, notes, device enrollment
├── frost_handlers.go         # FROST DKG + signing endpoints (v2)
├── signal_handlers.go        # Signal key upload, bundle fetch, messaging
├── dynamo.go                 # DynamoDB operations
├── models.go                 # Data models
└── webauthn.go               # WebAuthn configuration

enclave/                      # Nitro Enclave application (Go)
├── main.go                   # HTTP server (vsock or TCP)
├── vsock.go                  # vsock listener
├── Dockerfile                # Multi-stage build for EIF
├── frost/
│   ├── handlers.go           # FROST DKG round1 + round2 + complete
│   ├── signing.go            # Threshold signing (begin + finish)
│   └── types.go              # Session management (bounded map)
└── seal/
    ├── seal.go               # Sealer interface
    ├── kms.go                # KMS sealer with NSM attestation
    └── mock.go               # Mock sealer (dev mode only)

frost-wasm/                   # FROST WebAssembly module (Go → WASM)
├── main.go                   # WASM exports: DKG rounds, sign begin/finish
└── go.mod                    # depends on github.com/bytemare/frost

web/                          # Frontend SPA
├── index.html                # Single-page app shell
├── app.js                    # Auth flows, UI state machine, note encryption
├── frost.js                  # WASM bridge for FROST DKG + signing
├── signal.js                 # Signal key derivation, generation, upload
├── frost.wasm                # Compiled FROST WASM binary
├── wasm_exec.js              # Go WASM runtime
└── *.min.js                  # noble-secp256k1, simplewebauthn, qrcode

ios/                          # Native iOS app (Swift)
└── bkawk/
    ├── ContentView.swift     # State machine (enrol → auth → notes)
    ├── Services/
    │   ├── APIClient.swift       # API client with Signal key endpoints
    │   ├── SecureEnclaveService.swift  # P-256 key gen, ECDH, signing
    │   ├── CryptoService.swift   # AES-GCM, HKDF, base64url
    │   ├── KeychainService.swift # Credential storage
    │   └── SignalKeyService.swift # Signal key generation (CryptoKit Curve25519)
    └── Views/
        ├── QRScannerView.swift   # QR code scanning for enrollment
        ├── EnrolmentView.swift   # Multi-step enrollment flow
        ├── NotesView.swift       # Encrypted notes
        └── SettingsView.swift    # Device management

infra/                        # AWS CDK (TypeScript)
├── lib/
│   ├── passkey-signal-stack.ts          # VPC, Lambda, API Gateway, DynamoDB, CloudFront
│   └── passkey-signal-enclave-stack.ts  # EC2 (Nitro), KMS, S3 deploy bucket

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
| FROST protocol | 2-of-2 threshold DKG + Schnorr signing (secp256k1, RFC 9591) via `bytemare/frost` |
| Client share encryption | AES-256-GCM with HKDF-SHA256 key from WebAuthn PRF, random 32-byte salt |
| Enclave share sealing | KMS GenerateDataKey with Nitro attestation, AES-256-GCM envelope |
| KMS binding | PCR0 attestation condition auto-applied on every EIF build |
| Threshold signing | Partial Schnorr signatures aggregated by enclave; full key never reconstructed |
| Signal identity keys | Ed25519 (web: PRF-derived via HKDF; iOS: CryptoKit random) |
| Signal prekeys | X25519 key agreement with Ed25519-signed public keys |
| Signal OTPKs | Single-use X25519 keys, server-side atomic consumption |

### Infrastructure

| Feature | Implementation |
|---------|---------------|
| Enclave isolation | AWS Nitro Enclave (vsock only, no network, no persistent storage) |
| Enclave startup guard | Refuses MockSealer in production (vsock mode requires NSM device) |
| Session limits | Max 1000 concurrent FROST sessions, 10-minute TTL, UUID validation |
| Network | Lambda in private VPC subnets, enclave reachable only via Lambda security group |
| Auth tokens | SHA-256 hashed, TTL-bound, single-use OTP with constant-time comparison |
| Rate limiting | 5 OTP requests/phone/hour, API Gateway throttle (100 req/s) |
| CSP | `script-src 'self' 'wasm-unsafe-eval'`; `connect-src 'self'` + API origin |
| CORS | Explicit origin allowlist |

## API Endpoints

### Authentication
- `POST /auth/otp/request` — Send SMS OTP
- `POST /auth/otp/verify` — Verify OTP, return auth token
- `POST /auth/passkey/register/begin` — Start passkey registration
- `POST /auth/passkey/register/finish` — Complete passkey registration
- `POST /auth/passkey/auth/begin` — Start passkey authentication
- `POST /auth/passkey/auth/finish` — Complete passkey authentication

### FROST DKG + Signing
- `POST /v2/dkg/session` — Create FROST DKG session
- `POST /v2/dkg/round1` — Commitment exchange
- `POST /v2/dkg/round2` — Share exchange
- `POST /v2/dkg/complete` — Finalize, seal enclave share
- `POST /v2/sign/begin` — Nonce commitments
- `POST /v2/sign/finish` — Aggregate partial signatures

### Signal Keys
- `POST /v1/signal/keys/upload` — Upload identity + signed prekey + OTPKs
- `GET /v1/signal/keys/bundle` — Fetch PreKey bundle (consumes one OTPK)
- `POST /v1/signal/keys/replenish` — Upload more OTPKs
- `GET /v1/signal/keys/count` — Check remaining unused OTPKs

### Device Management
- `POST /device/enrol/redeem` — Redeem QR enrollment token
- `GET /device/enrol/receive` — Poll for master key delivery
- `POST /device/enrol/complete` — Finalize device enrollment
- `POST /device/auth` — Request device auth challenge
- `POST /device/verify` — Verify device signature

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

### FROST WASM (rebuild after frost-wasm/ changes)

```bash
cd frost-wasm && GOOS=js GOARCH=wasm go build -o ../web/frost.wasm .
```

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
