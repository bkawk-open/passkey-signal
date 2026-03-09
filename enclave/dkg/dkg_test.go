package dkg

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func TestFullCeremony(t *testing.T) {
	sessionID := "test-enclave-ceremony"

	clientPriv, _ := secp256k1.GeneratePrivateKey()
	clientPub := clientPriv.PubKey()
	clientPubHex := hex.EncodeToString(clientPub.SerializeCompressed())

	clientCommit, clientResp, err := GenerateSchnorrProof(clientPriv, clientPub, sessionID)
	if err != nil {
		t.Fatalf("client proof gen: %v", err)
	}

	status, resp := HandleRound1(Round1Request{
		SessionID:   sessionID,
		PublicPoint: clientPubHex,
		Proof:       Proof{Commitment: clientCommit, Response: clientResp},
	})
	if status != 200 {
		t.Fatalf("round1 status %d: %v", status, resp)
	}

	r1 := resp.(Round1Response)

	enclavePubBytes, _ := hex.DecodeString(r1.PublicPoint)
	enclavePub, _ := secp256k1.ParsePubKey(enclavePubBytes)

	if !VerifySchnorrProof(enclavePub, sessionID, r1.Proof.Commitment, r1.Proof.Response) {
		t.Fatal("enclave proof should verify")
	}

	jointPub := AddPublicKeys(clientPub, enclavePub)
	jointPubHex := hex.EncodeToString(jointPub.SerializeCompressed())
	confirmHash := sha256.Sum256([]byte("DKG-CONFIRM-v1:" + sessionID + jointPubHex))

	status2, resp2 := HandleComplete(CompleteRequest{
		SessionID:        sessionID,
		JointPublicKey:   jointPubHex,
		ConfirmationHash: hex.EncodeToString(confirmHash[:]),
	})
	if status2 != 200 {
		t.Fatalf("complete status %d: %v", status2, resp2)
	}

	r2 := resp2.(CompleteResponse)
	if r2.JointPublicKey != jointPubHex {
		t.Fatal("joint key mismatch")
	}
	if r2.SealedShareB == "" {
		t.Fatal("sealed share B should not be empty")
	}
	if r2.SealMode != "mock" {
		t.Fatalf("expected mock seal mode, got %s", r2.SealMode)
	}
}

func TestSessionConsumed(t *testing.T) {
	sessionID := "consume-enclave-test"

	k, _ := secp256k1.GeneratePrivateKey()
	pub := k.PubKey()
	pubHex := hex.EncodeToString(pub.SerializeCompressed())
	c, r, _ := GenerateSchnorrProof(k, pub, sessionID)

	HandleRound1(Round1Request{
		SessionID:   sessionID,
		PublicPoint: pubHex,
		Proof:       Proof{Commitment: c, Response: r},
	})

	// Run round1 again to get a fresh session
	s, resp := HandleRound1(Round1Request{
		SessionID:   sessionID,
		PublicPoint: pubHex,
		Proof:       Proof{Commitment: c, Response: r},
	})
	if s != 200 {
		t.Fatalf("round1: %v", resp)
	}
	r1 := resp.(Round1Response)

	epb, _ := hex.DecodeString(r1.PublicPoint)
	ep, _ := secp256k1.ParsePubKey(epb)
	jp := AddPublicKeys(pub, ep)
	jpHex := hex.EncodeToString(jp.SerializeCompressed())
	ch := sha256.Sum256([]byte("DKG-CONFIRM-v1:" + sessionID + jpHex))

	req := CompleteRequest{
		SessionID:        sessionID,
		JointPublicKey:   jpHex,
		ConfirmationHash: hex.EncodeToString(ch[:]),
	}

	s1, _ := HandleComplete(req)
	if s1 != 200 {
		t.Fatal("first complete should succeed")
	}

	s2, _ := HandleComplete(req)
	if s2 != 400 {
		t.Fatal("second complete should fail")
	}
}

func TestInvalidProofRejected(t *testing.T) {
	k, _ := secp256k1.GeneratePrivateKey()
	pubHex := hex.EncodeToString(k.PubKey().SerializeCompressed())

	s, _ := HandleRound1(Round1Request{
		SessionID:   "test",
		PublicPoint: pubHex,
		Proof: Proof{
			Commitment: pubHex,
			Response:   "0000000000000000000000000000000000000000000000000000000000000000",
		},
	})
	if s != 400 {
		t.Fatalf("expected 400 for bad proof, got %d", s)
	}
}
