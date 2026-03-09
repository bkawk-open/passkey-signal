# Plan: libsignal Key Pairs + FROST DKG Upgrade

## Context

The passkey-signal project currently uses a simple two-party additive DKG where client and enclave each generate a secp256k1 key pair and combine public keys via point addition. This has two limitations: (1) signing requires reconstructing the full private key, making the wallet partially custodial, and (2) there's no per-credential identity key infrastructure for future E2E messaging. This plan adds per-passkey Signal Protocol identity keys and PreKey bundles (the authentication/key-management layer), then upgrades the DKG to FROST so the wallet private key is never reconstructed during signing.

### Scope

**In scope**: key derivation, key generation, encrypted key storage, PreKey bundle upload/fetch/replenish, FROST DKG ceremony, FROST threshold signing protocol.

**Out of scope** (handled by separate services later): X3DH session initiation, Double Ratchet messaging, message send/receive/poll/delete, messaging UI, transaction construction and broadcast.

---

## Phase 1: libsignal Key Pairs & PreKey Bundle Infrastructure

### Goal
Each passkey/credential gets its own Curve25519 identity key pair. PreKey bundles are generated, encrypted, and stored server-side so that other services can later use them to establish Signal Protocol sessions. This phase only builds the key lifecycle — no session establishment or messaging.

### Key Design Decisions

- **Per-credential identity keys** (not per-user): each passkey registration generates a unique Ed25519/X25519 identity key pair, derived deterministically from the WebAuthn PRF output + credential ID via HKDF
- **Server stores public keys + encrypted private keys**: Signed PreKeys and One-Time PreKeys are randomly generated, encrypted with PRF-derived AES key, stored in DynamoDB so they survive browser storage loss
- **Server is untrusted**: never sees plaintext private keys; only stores encrypted blobs and public keys

### 1.1 Extend noble-curves bundle

**File**: `/tmp/noble-bundle/entry.js` → rebuild `web/noble-secp256k1.min.js`

Add exports for Ed25519 and X25519 from `@noble/curves/ed25519`. The existing bundle already has secp256k1, SHA-256, and HKDF.

### 1.2 Create `web/signal.js`

New browser-side module exposing key generation and bundle management only:

- `deriveSignalIdentityKey(prfOutput, credentialId)` — HKDF-SHA256 with info=`"signal-identity-v1:" + credentialId`, produces Ed25519 seed
- `generateSignedPreKey(identityPrivKey, keyId)` — random X25519 key pair, sign public key with identity key
- `generateOneTimePreKeys(startId, count)` — batch of random X25519 key pairs
- `encryptPreKeyPrivate(prfOutput, credentialId, privKeyBytes)` — AES-256-GCM with HKDF-derived key (same pattern as wallet share encryption in `dkg.js`)
- `uploadKeyBundle(apiBase, token, bundle)` — POST to `/v1/signal/keys`
- `fetchPreKeyBundle(apiBase, token, targetPhone)` — GET bundle for session initiation (used by downstream services)

**Library choice**: Use `@noble/curves` primitives (X25519 ECDH, Ed25519 signing, HKDF, AES-256-GCM via SubtleCrypto). No X3DH or Double Ratchet implementation in this phase — those belong to the messaging service.

### 1.3 DynamoDB data model additions

**File**: `api/models.go`

```
SignalIdentityItem
  PK: "USER#{phone}"
  SK: "SIGIDENT#{credentialID}"
  CredentialID, IdentityPublicKey (Ed25519, base64url)
  CreatedAt

SignalSignedPreKeyItem
  PK: "USER#{phone}"
  SK: "SIGSPK#{credentialID}#{keyId}"
  KeyId, PublicKey, Signature, EncryptedPrivateKey, IV, Salt
  ExpiresAt, CreatedAt

SignalOneTimePreKeyItem
  PK: "USER#{phone}"
  SK: "SIGOTPK#{credentialID}#{keyId}"
  KeyId, PublicKey, EncryptedPrivateKey, IV, Salt
  Consumed (bool)
```

No `SignalMessageItem` — message storage is out of scope.

### 1.4 API endpoints

**Files**: `api/signal_handlers.go` (new), `api/dynamo.go` (extend), `api/main.go` (add routes)

```
POST /v1/signal/keys/upload     — Upload identity pub key + signed prekey + OTPKs
GET  /v1/signal/keys/bundle     — Fetch a user's PreKey bundle (consumes one OTPK atomically)
POST /v1/signal/keys/replenish  — Upload more OTPKs
GET  /v1/signal/keys/count      — Check remaining unused OTPKs
```

All endpoints require Bearer token auth (existing auth middleware). No message endpoints — those belong to a messaging service.

### 1.5 Integrate into `web/app.js`

After passkey registration or login (when PRF output is available):
1. Derive Signal identity key from PRF + credential ID
2. Check if keys have been uploaded for this credential (`/v1/signal/keys/count`)
3. If not, generate signed prekey + 20 OTPKs, encrypt private keys, upload bundle
4. On each login, check OTPK count and replenish if below 5

---

## Phase 2: FROST DKG + Threshold Signing

### Goal
Replace the additive 2-party DKG with FROST (RFC 9591) so that:
- The wallet private key is never reconstructed during signing
- Each party computes a partial signature; the coordinator aggregates
- 2-of-2 threshold: client + enclave both required

This phase builds the DKG ceremony and the threshold signing protocol. Actual transaction construction and broadcast are out of scope — downstream services call the signing endpoints.

### Key Design Decisions

- **2-of-2 threshold**: same trust model as current (both parties required), but private key never reconstructed
- **Go WASM for browser**: compile `bytemare/frost` to WASM for identical crypto on both sides
- **v2 API endpoints**: coexist with v1 for backward compatibility
- **Enclave sealed share**: same KMS sealing mechanism, just sealing a FROST signing share instead of raw private key

### 2.1 FROST WASM module

**New directory**: `frost-wasm/`

```
frost-wasm/
  main.go     — WASM exports: frostDKGRound1(), frostDKGRound2(), frostSignBegin(), frostSignFinish()
  go.mod      — depends on github.com/bytemare/frost (Secp256k1-SHA256 ciphersuite)
```

Build: `GOOS=js GOARCH=wasm go build -o web/frost.wasm ./frost-wasm/`

Functions accept/return JSON strings across the JS↔Go boundary. The WASM binary is lazy-loaded only when DKG or signing is needed.

### 2.2 Enclave FROST handlers

**New package**: `enclave/frost/`

```
enclave/frost/
  types.go      — FROST session state, request/response structs
  handlers.go   — HandleFrostRound1, HandleFrostRound2, HandleFrostComplete
  signing.go    — HandleSignBegin, HandleSignFinish
```

**DKG flow** (2-of-2, Pedersen):

```
Round 1 (Commitment):
  Client → enclave: polynomial commitment C_1 + ZKP
  Enclave → client: polynomial commitment C_2 + ZKP

Round 2 (Share Exchange):
  Client → enclave: f_1(2) encrypted to enclave's commitment
  Enclave → client: f_2(1) encrypted to client's commitment
  Both verify received shares against commitments

Complete:
  Client computes signing share s_1 = f_1(1) + f_2(1)
  Enclave computes signing share s_2 = f_1(2) + f_2(2), seals with KMS
  Group public key Y = C_1[0] + C_2[0]
```

**Signing flow** (2-of-2 FROST):

```
Sign Begin:
  Client → enclave: nonce commitment (D_1, E_1), message hash
  Enclave → client: nonce commitment (D_2, E_2)

Sign Finish:
  Client → enclave: partial signature z_1
  Enclave computes z_2, aggregates: sig = (R, z_1 + z_2)
  Returns standard Schnorr signature verifiable with group key Y
```

**Dependency**: Add `github.com/bytemare/frost` to `enclave/go.mod`

### 2.3 v2 API endpoints

**Files**: `api/frost_handlers.go` (new), `api/main.go` (add routes)

```
POST /v2/dkg/session    — Create FROST DKG session (auth required)
POST /v2/dkg/round1     — FROST DKG round 1 (commitment exchange)
POST /v2/dkg/round2     — FROST DKG round 2 (share exchange)
POST /v2/dkg/complete   — Finalize, seal enclave share

POST /v2/sign/begin     — Begin FROST signing (nonce commitments)
POST /v2/sign/finish    — Exchange partial sigs, return aggregated Schnorr sig
```

Lambda proxies to enclave when `ENCLAVE_URL` is set, otherwise uses embedded mock (same pattern as v1). Transaction construction/broadcast is not handled here — callers provide a pre-hashed message.

### 2.4 WalletItem changes

**File**: `api/models.go`

Add fields to `WalletItem`:
- `DKGVersion` — `"v1"` (additive) or `"v2"` (FROST), defaults to `"v1"` for existing
- `GroupCommitments` — verification data from DKG (JSON, for v2 only)

The `SealedShareB` field changes semantics in v2 (FROST signing share scalar instead of raw private key) but is still a sealed 32-byte value using the same KMS mechanism.

### 2.5 Browser-side FROST

**New file**: `web/frost.js`

- Lazy-loads `frost.wasm` + Go WASM runtime (`wasm_exec.js`)
- Wraps WASM exports with async JS functions
- Handles the multi-round HTTP flow with the API
- Exposes `window.FROST.runDKG(apiBase, sessionID, authToken)` and `window.FROST.sign(apiBase, walletId, messageHash, authToken)`

**File**: `web/app.js` — update DKG flow to use `window.FROST.runDKG()` for new wallets, keep `window.DKG.runClientDKG()` as fallback for v1

### 2.6 Migration

- No forced migration: v1 wallets continue to work
- New wallets default to v2 (FROST)
- v1 endpoints remain functional
- Enclave supports both seal formats (determined by `DKGVersion` on WalletItem)

---

## Implementation Order

### Phase 1: libsignal key infrastructure (do first)
1. Extend noble bundle with Ed25519/X25519
2. Create `web/signal.js` — identity key derivation, PreKey generation, encrypted storage
3. Add Signal DynamoDB structs to `api/models.go`
4. Add Signal CRUD functions to `api/dynamo.go`
5. Create `api/signal_handlers.go` with key upload/fetch/replenish/count endpoints
6. Wire routes in `api/main.go`
7. Integrate key generation into `web/app.js` registration/login flow

### Phase 2: FROST (do second)
1. Create `frost-wasm/` module, verify WASM builds
2. Add `bytemare/frost` to enclave, create `enclave/frost/` package
3. Implement DKG handlers (round1, round2, complete)
4. Implement signing handlers (begin, finish)
5. Create `api/frost_handlers.go` with v2 endpoints
6. Create `web/frost.js` WASM bridge
7. Extend `WalletItem` with version field
8. Update `web/app.js` to use FROST for new wallets
9. End-to-end test: DKG ceremony → threshold sign → verify signature

---

## Files to Modify/Create

| File | Action | Phase |
|------|--------|-------|
| `/tmp/noble-bundle/entry.js` | Extend with Ed25519/X25519 | 1 |
| `web/noble-secp256k1.min.js` | Rebuild | 1 |
| `web/signal.js` | **Create** — identity key derivation, PreKey generation, bundle management | 1 |
| `web/index.html` | Add `<script src="signal.js">` | 1 |
| `api/models.go` | Add Signal key items + extend WalletItem | 1+2 |
| `api/dynamo.go` | Add Signal key CRUD functions | 1 |
| `api/signal_handlers.go` | **Create** — key upload/fetch/replenish/count endpoints | 1 |
| `api/main.go` | Add Signal + FROST routes | 1+2 |
| `web/app.js` | Integrate Signal key gen + FROST DKG | 1+2 |
| `frost-wasm/main.go` | **Create** — WASM exports | 2 |
| `frost-wasm/go.mod` | **Create** | 2 |
| `enclave/frost/types.go` | **Create** — session types | 2 |
| `enclave/frost/handlers.go` | **Create** — DKG handlers | 2 |
| `enclave/frost/signing.go` | **Create** — threshold signing | 2 |
| `enclave/go.mod` | Add bytemare/frost dependency | 2 |
| `enclave/main.go` | Add FROST routes | 2 |
| `web/frost.js` | **Create** — WASM bridge | 2 |
| `api/frost_handlers.go` | **Create** — v2 DKG + signing endpoints | 2 |

## Existing Code to Reuse

- `enclave/seal/` — Sealer interface unchanged, seals FROST shares identically
- `api/dynamo.go` patterns — all new CRUD follows existing `attributevalue.MarshalMap` / `PutItem` pattern
- `web/dkg.js` — hex helpers, AES-GCM encryption pattern reused in `signal.js`
- `enclave/dkg/handlers.go` — session management pattern (bounded map, TTL, UUID validation)
- CDK infrastructure — no changes needed, same VPC/Lambda/enclave/KMS

## Verification

### Phase 1
- Register a passkey → verify Signal identity key is derived and uploaded
- Log in on second device → verify different identity key (different credential ID)
- Fetch PreKey bundle for another user → verify bundle returned with one OTPK consumed
- Clear browser storage, re-login → verify identity key is re-derived identically from PRF
- OTPK count drops after bundle fetch; replenish restores count

### Phase 2
- Run FROST DKG ceremony → verify group public key matches expected
- Check enclave sealed share is a FROST signing share (not raw private key)
- Execute threshold sign → verify resulting Schnorr signature validates against group key
- Verify full private key is never present in memory on either side during signing
- Test v1 wallets still work alongside v2
- WASM bundle loads and executes correctly in browser
