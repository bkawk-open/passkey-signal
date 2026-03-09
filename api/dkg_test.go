package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// --- Schnorr proof tests ---

func TestSchnorrProofRoundTrip(t *testing.T) {
	privKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("key generation: %v", err)
	}
	pubKey := privKey.PubKey()
	sessionID := "test-session-123"

	commitHex, respHex, err := generateSchnorrProof(privKey, pubKey, sessionID)
	if err != nil {
		t.Fatalf("proof generation: %v", err)
	}

	if !verifySchnorrProof(pubKey, sessionID, commitHex, respHex) {
		t.Fatal("valid proof should verify")
	}
}

func TestSchnorrProofWrongSession(t *testing.T) {
	privKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("key generation: %v", err)
	}
	pubKey := privKey.PubKey()

	commitHex, respHex, err := generateSchnorrProof(privKey, pubKey, "session-A")
	if err != nil {
		t.Fatalf("proof generation: %v", err)
	}

	if verifySchnorrProof(pubKey, "session-B", commitHex, respHex) {
		t.Fatal("proof with wrong session should not verify")
	}
}

func TestSchnorrProofWrongKey(t *testing.T) {
	privKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("key generation: %v", err)
	}
	pubKey := privKey.PubKey()
	sessionID := "test-session"

	commitHex, respHex, err := generateSchnorrProof(privKey, pubKey, sessionID)
	if err != nil {
		t.Fatalf("proof generation: %v", err)
	}

	otherKey, _ := secp256k1.GeneratePrivateKey()
	if verifySchnorrProof(otherKey.PubKey(), sessionID, commitHex, respHex) {
		t.Fatal("proof with wrong public key should not verify")
	}
}

func TestSchnorrProofInvalidHex(t *testing.T) {
	privKey, _ := secp256k1.GeneratePrivateKey()
	pubKey := privKey.PubKey()

	if verifySchnorrProof(pubKey, "s", "not-hex", "also-not-hex") {
		t.Fatal("invalid hex should not verify")
	}
}

// --- DKG challenge tests ---

func TestComputeDKGChallengeDeterministic(t *testing.T) {
	privKey, _ := secp256k1.GeneratePrivateKey()
	pubKey := privKey.PubKey()
	commitKey, _ := secp256k1.GeneratePrivateKey()
	commitment := commitKey.PubKey()

	e1 := computeDKGChallenge("session", pubKey, commitment)
	e2 := computeDKGChallenge("session", pubKey, commitment)

	b1 := e1.Bytes()
	b2 := e2.Bytes()
	if b1 != b2 {
		t.Fatal("same inputs should produce same challenge")
	}
}

func TestComputeDKGChallengeDifferentSessions(t *testing.T) {
	privKey, _ := secp256k1.GeneratePrivateKey()
	pubKey := privKey.PubKey()
	commitKey, _ := secp256k1.GeneratePrivateKey()
	commitment := commitKey.PubKey()

	e1 := computeDKGChallenge("session-1", pubKey, commitment)
	e2 := computeDKGChallenge("session-2", pubKey, commitment)

	b1 := e1.Bytes()
	b2 := e2.Bytes()
	if b1 == b2 {
		t.Fatal("different sessions should produce different challenges")
	}
}

// --- Public key addition tests ---

func TestAddPublicKeys(t *testing.T) {
	k1, _ := secp256k1.GeneratePrivateKey()
	k2, _ := secp256k1.GeneratePrivateKey()

	joint := addPublicKeys(k1.PubKey(), k2.PubKey())

	// Joint key should be a valid point (33 bytes compressed)
	compressed := joint.SerializeCompressed()
	if len(compressed) != 33 {
		t.Fatalf("expected 33-byte compressed key, got %d", len(compressed))
	}

	// Should be parseable
	_, err := secp256k1.ParsePubKey(compressed)
	if err != nil {
		t.Fatalf("joint key should be parseable: %v", err)
	}
}

func TestAddPublicKeysCommutative(t *testing.T) {
	k1, _ := secp256k1.GeneratePrivateKey()
	k2, _ := secp256k1.GeneratePrivateKey()

	j1 := addPublicKeys(k1.PubKey(), k2.PubKey())
	j2 := addPublicKeys(k2.PubKey(), k1.PubKey())

	if hex.EncodeToString(j1.SerializeCompressed()) != hex.EncodeToString(j2.SerializeCompressed()) {
		t.Fatal("point addition should be commutative")
	}
}

// --- Full DKG ceremony test ---

func TestFullDKGCeremony(t *testing.T) {
	sessionID := "test-dkg-ceremony"

	// Client generates key pair and proof
	clientPriv, _ := secp256k1.GeneratePrivateKey()
	clientPub := clientPriv.PubKey()
	clientPubHex := hex.EncodeToString(clientPub.SerializeCompressed())

	clientCommit, clientResp, err := generateSchnorrProof(clientPriv, clientPub, sessionID)
	if err != nil {
		t.Fatalf("client proof gen: %v", err)
	}

	// Simulate round1 handler
	r1Body, _ := json.Marshal(dkgRound1Request{
		SessionID:   sessionID,
		PublicPoint: clientPubHex,
		Proof:       dkgProof{Commitment: clientCommit, Response: clientResp},
	})

	r1Resp, err := handleDKGRound1(string(r1Body))
	if err != nil {
		t.Fatalf("round1 handler: %v", err)
	}
	if r1Resp.StatusCode != 200 {
		t.Fatalf("round1 status %d: %s", r1Resp.StatusCode, r1Resp.Body)
	}

	var r1Data dkgRound1Response
	json.Unmarshal([]byte(r1Resp.Body), &r1Data)

	// Verify enclave's proof
	if !verifySchnorrProof(mustParsePubKey(t, r1Data.PublicPoint), sessionID, r1Data.Proof.Commitment, r1Data.Proof.Response) {
		t.Fatal("enclave proof should verify")
	}

	// Compute joint key
	enclavePub := mustParsePubKey(t, r1Data.PublicPoint)
	jointPub := addPublicKeys(clientPub, enclavePub)
	jointPubHex := hex.EncodeToString(jointPub.SerializeCompressed())

	// Compute confirmation hash
	confirmInput := []byte("DKG-CONFIRM-v1:" + sessionID + jointPubHex)
	confirmHash := sha256.Sum256(confirmInput)
	confirmHashHex := hex.EncodeToString(confirmHash[:])

	// Simulate complete handler
	completeBody, _ := json.Marshal(dkgCompleteRequest{
		SessionID:        sessionID,
		JointPublicKey:   jointPubHex,
		ConfirmationHash: confirmHashHex,
	})

	r2Resp, err := handleDKGComplete(string(completeBody))
	if err != nil {
		t.Fatalf("complete handler: %v", err)
	}
	if r2Resp.StatusCode != 200 {
		t.Fatalf("complete status %d: %s", r2Resp.StatusCode, r2Resp.Body)
	}

	var r2Data dkgCompleteResponse
	json.Unmarshal([]byte(r2Resp.Body), &r2Data)

	if r2Data.JointPublicKey != jointPubHex {
		t.Fatal("joint public key mismatch")
	}
	if r2Data.SealedShareB == "" {
		t.Fatal("sealed share B should not be empty")
	}
	if r2Data.SealMode != "mock" {
		t.Fatalf("expected mock seal mode, got %s", r2Data.SealMode)
	}
}

// --- DKG handler error cases ---

func TestDKGRound1InvalidJSON(t *testing.T) {
	resp, _ := handleDKGRound1("not json")
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestDKGRound1MissingSession(t *testing.T) {
	body, _ := json.Marshal(dkgRound1Request{PublicPoint: "aa"})
	resp, _ := handleDKGRound1(string(body))
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestDKGRound1InvalidProof(t *testing.T) {
	k, _ := secp256k1.GeneratePrivateKey()
	pubHex := hex.EncodeToString(k.PubKey().SerializeCompressed())

	body, _ := json.Marshal(dkgRound1Request{
		SessionID:   "test",
		PublicPoint: pubHex,
		Proof: dkgProof{
			Commitment: pubHex, // wrong: using pubkey as commitment
			Response:   "0000000000000000000000000000000000000000000000000000000000000000",
		},
	})
	resp, _ := handleDKGRound1(string(body))
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for bad proof, got %d: %s", resp.StatusCode, resp.Body)
	}
}

func TestDKGCompleteInvalidJSON(t *testing.T) {
	resp, _ := handleDKGComplete("bad")
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestDKGCompleteUnknownSession(t *testing.T) {
	body, _ := json.Marshal(dkgCompleteRequest{SessionID: "does-not-exist"})
	resp, _ := handleDKGComplete(string(body))
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestDKGCompleteWrongJointKey(t *testing.T) {
	sessionID := "wrong-joint-test"

	// Run round1 to create a session
	clientPriv, _ := secp256k1.GeneratePrivateKey()
	clientPub := clientPriv.PubKey()
	clientPubHex := hex.EncodeToString(clientPub.SerializeCompressed())
	commit, resp, _ := generateSchnorrProof(clientPriv, clientPub, sessionID)

	r1Body, _ := json.Marshal(dkgRound1Request{
		SessionID:   sessionID,
		PublicPoint: clientPubHex,
		Proof:       dkgProof{Commitment: commit, Response: resp},
	})
	r1Resp, _ := handleDKGRound1(string(r1Body))
	if r1Resp.StatusCode != 200 {
		t.Fatalf("round1 failed: %s", r1Resp.Body)
	}

	// Send wrong joint key
	wrongKey, _ := secp256k1.GeneratePrivateKey()
	wrongPubHex := hex.EncodeToString(wrongKey.PubKey().SerializeCompressed())

	completeBody, _ := json.Marshal(dkgCompleteRequest{
		SessionID:        sessionID,
		JointPublicKey:   wrongPubHex,
		ConfirmationHash: "0000",
	})
	r2Resp, _ := handleDKGComplete(string(completeBody))
	if r2Resp.StatusCode != 400 {
		t.Fatalf("expected 400 for wrong joint key, got %d: %s", r2Resp.StatusCode, r2Resp.Body)
	}
}

func TestDKGCompleteWrongConfirmationHash(t *testing.T) {
	sessionID := "wrong-hash-test"

	clientPriv, _ := secp256k1.GeneratePrivateKey()
	clientPub := clientPriv.PubKey()
	clientPubHex := hex.EncodeToString(clientPub.SerializeCompressed())
	commit, resp, _ := generateSchnorrProof(clientPriv, clientPub, sessionID)

	r1Body, _ := json.Marshal(dkgRound1Request{
		SessionID:   sessionID,
		PublicPoint: clientPubHex,
		Proof:       dkgProof{Commitment: commit, Response: resp},
	})
	r1Resp, _ := handleDKGRound1(string(r1Body))
	if r1Resp.StatusCode != 200 {
		t.Fatalf("round1 failed: %s", r1Resp.Body)
	}

	var r1Data dkgRound1Response
	json.Unmarshal([]byte(r1Resp.Body), &r1Data)

	enclavePub := mustParsePubKey(t, r1Data.PublicPoint)
	jointPub := addPublicKeys(clientPub, enclavePub)
	jointPubHex := hex.EncodeToString(jointPub.SerializeCompressed())

	completeBody, _ := json.Marshal(dkgCompleteRequest{
		SessionID:        sessionID,
		JointPublicKey:   jointPubHex,
		ConfirmationHash: "wrong-hash",
	})
	r2Resp, _ := handleDKGComplete(string(completeBody))
	if r2Resp.StatusCode != 400 {
		t.Fatalf("expected 400 for wrong hash, got %d: %s", r2Resp.StatusCode, r2Resp.Body)
	}
}

func TestDKGSessionConsumedAfterComplete(t *testing.T) {
	sessionID := "consume-test"

	clientPriv, _ := secp256k1.GeneratePrivateKey()
	clientPub := clientPriv.PubKey()
	clientPubHex := hex.EncodeToString(clientPub.SerializeCompressed())
	commit, resp, _ := generateSchnorrProof(clientPriv, clientPub, sessionID)

	r1Body, _ := json.Marshal(dkgRound1Request{
		SessionID:   sessionID,
		PublicPoint: clientPubHex,
		Proof:       dkgProof{Commitment: commit, Response: resp},
	})
	handleDKGRound1(string(r1Body))

	var r1Data dkgRound1Response
	r1Resp, _ := handleDKGRound1(string(r1Body))
	// Second round1 with same session overwrites — that's ok
	json.Unmarshal([]byte(r1Resp.Body), &r1Data)

	// Do a fresh round1 to get a valid session
	r1Resp2, _ := handleDKGRound1(string(r1Body))
	json.Unmarshal([]byte(r1Resp2.Body), &r1Data)

	enclavePub := mustParsePubKey(t, r1Data.PublicPoint)
	jointPub := addPublicKeys(clientPub, enclavePub)
	jointPubHex := hex.EncodeToString(jointPub.SerializeCompressed())
	confirmHash := sha256.Sum256([]byte("DKG-CONFIRM-v1:" + sessionID + jointPubHex))

	completeBody, _ := json.Marshal(dkgCompleteRequest{
		SessionID:        sessionID,
		JointPublicKey:   jointPubHex,
		ConfirmationHash: hex.EncodeToString(confirmHash[:]),
	})

	// First complete should succeed
	c1, _ := handleDKGComplete(string(completeBody))
	if c1.StatusCode != 200 {
		t.Fatalf("first complete should succeed, got %d: %s", c1.StatusCode, c1.Body)
	}

	// Second complete should fail — session consumed
	c2, _ := handleDKGComplete(string(completeBody))
	if c2.StatusCode != 400 {
		t.Fatalf("second complete should fail, got %d", c2.StatusCode)
	}
}

// --- DKGSessionItem model tests ---

func TestDKGSessionItemFields(t *testing.T) {
	item := DKGSessionItem{
		PK:        "DKG#abc-123",
		SK:        "SESSION",
		UserID:    "user-456",
		Phone:     "+44123456789",
		ExpiresAt: "2026-03-09T12:00:00Z",
		TTL:       1773100800,
	}

	if item.PK != "DKG#abc-123" {
		t.Fatal("PK mismatch")
	}
	if item.SK != "SESSION" {
		t.Fatal("SK mismatch")
	}
	if item.UserID != "user-456" {
		t.Fatal("UserID mismatch")
	}
	if item.Phone != "+44123456789" {
		t.Fatal("Phone mismatch")
	}
	if item.TTL != 1773100800 {
		t.Fatal("TTL mismatch")
	}
}

// --- Helper ---

func mustParsePubKey(t *testing.T, hexStr string) *secp256k1.PublicKey {
	t.Helper()
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	pk, err := secp256k1.ParsePubKey(b)
	if err != nil {
		t.Fatalf("parse pubkey: %v", err)
	}
	return pk
}
