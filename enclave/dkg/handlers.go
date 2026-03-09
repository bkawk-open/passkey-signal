package dkg

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"regexp"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var uuidRegex = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func HandleRound1(req Round1Request) (int, interface{}) {
	if req.SessionID == "" || !uuidRegex.MatchString(req.SessionID) {
		return 400, map[string]string{"error": "invalid session", "code": "INVALID_REQUEST"}
	}

	clientPubBytes, err := hex.DecodeString(req.PublicPoint)
	if err != nil {
		return 400, map[string]string{"error": "invalid request", "code": "INVALID_REQUEST"}
	}
	clientPub, err := secp256k1.ParsePubKey(clientPubBytes)
	if err != nil {
		return 400, map[string]string{"error": "invalid request", "code": "INVALID_REQUEST"}
	}

	if !VerifySchnorrProof(clientPub, req.SessionID, req.Proof.Commitment, req.Proof.Response) {
		return 400, map[string]string{"error": "proof verification failed", "code": "INVALID_PROOF"}
	}

	privKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return 500, map[string]string{"error": "internal error", "code": "ENCLAVE_ERROR"}
	}
	pubKey := privKey.PubKey()

	commitHex, respHex, err := GenerateSchnorrProof(privKey, pubKey, req.SessionID)
	if err != nil {
		return 500, map[string]string{"error": "internal error", "code": "ENCLAVE_ERROR"}
	}

	sessionsMu.Lock()
	if len(sessions) >= maxSessions {
		sessionsMu.Unlock()
		log.Printf("session limit reached (%d), rejecting round1", maxSessions)
		return 503, map[string]string{"error": "service busy", "code": "CAPACITY_EXCEEDED"}
	}
	sessions[req.SessionID] = &session{
		privateKey:      privKey,
		publicPoint:     pubKey,
		clientPublicKey: clientPub,
		createdAt:       time.Now(),
	}
	sessionsMu.Unlock()

	log.Printf("DKG round1 complete for session %s", req.SessionID)
	return 200, Round1Response{
		PublicPoint: hex.EncodeToString(pubKey.SerializeCompressed()),
		Proof: Proof{
			Commitment: commitHex,
			Response:   respHex,
		},
	}
}

func HandleComplete(req CompleteRequest) (int, interface{}) {
	if req.SessionID == "" || !uuidRegex.MatchString(req.SessionID) {
		return 400, map[string]string{"error": "invalid session", "code": "INVALID_REQUEST"}
	}

	sessionsMu.Lock()
	sess, ok := sessions[req.SessionID]
	if ok {
		delete(sessions, req.SessionID)
	}
	sessionsMu.Unlock()

	if !ok {
		return 400, map[string]string{"error": "invalid or expired session", "code": "SESSION_ERROR"}
	}

	if time.Since(sess.createdAt) > 10*time.Minute {
		return 400, map[string]string{"error": "invalid or expired session", "code": "SESSION_ERROR"}
	}

	jointPub := AddPublicKeys(sess.clientPublicKey, sess.publicPoint)
	jointPubHex := hex.EncodeToString(jointPub.SerializeCompressed())

	if req.JointPublicKey != jointPubHex {
		return 400, map[string]string{"error": "joint public key mismatch", "code": "INVALID_REQUEST"}
	}

	expectedHash := sha256.Sum256([]byte("DKG-CONFIRM-v1:" + req.SessionID + jointPubHex))
	expectedHashHex := hex.EncodeToString(expectedHash[:])

	if req.ConfirmationHash != expectedHashHex {
		return 400, map[string]string{"error": "confirmation hash mismatch", "code": "INVALID_REQUEST"}
	}

	privKeyBytes := sess.privateKey.Serialize()
	sealedShareB, err := Sealer.Seal(privKeyBytes)
	if err != nil {
		log.Printf("seal error for session %s: %v", req.SessionID, err)
		return 500, map[string]string{"error": "seal failed", "code": "ENCLAVE_ERROR"}
	}
	sealMode := Sealer.Mode()

	log.Printf("DKG complete for session %s — joint key: %s...", req.SessionID, jointPubHex[:16])
	return 200, CompleteResponse{
		JointPublicKey: jointPubHex,
		SealedShareB:   sealedShareB,
		SealMode:       sealMode,
	}
}
