package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"regexp"
	"sync"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// dkgSession holds the enclave's in-memory state for a DKG ceremony.
type dkgSession struct {
	privateKey      *secp256k1.PrivateKey
	publicPoint     *secp256k1.PublicKey
	clientPublicKey *secp256k1.PublicKey
	createdAt       time.Time
}

const maxDKGSessions = 1000

var (
	dkgSessions   = make(map[string]*dkgSession)
	dkgSessionsMu sync.Mutex
	dkgUUIDRegex  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

type dkgRound1Request struct {
	SessionID   string   `json:"session_id"`
	PublicPoint string   `json:"public_point"`
	Proof       dkgProof `json:"proof"`
}

type dkgProof struct {
	Commitment string `json:"commitment"`
	Response   string `json:"response"`
}

type dkgRound1Response struct {
	PublicPoint string   `json:"public_point"`
	Proof       dkgProof `json:"proof"`
}

type dkgCompleteRequest struct {
	SessionID        string `json:"session_id"`
	JointPublicKey   string `json:"joint_public_key"`
	ConfirmationHash string `json:"confirmation_hash"`
}

type dkgCompleteResponse struct {
	JointPublicKey string `json:"joint_public_key"`
	SealedShareB   string `json:"sealed_share_b"`
	SealMode       string `json:"seal_mode"`
}

func handleDKGRound1(body string) (events.APIGatewayV2HTTPResponse, error) {
	var req dkgRound1Request
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		return jsonResp(400, map[string]string{"error": "invalid JSON", "code": "INVALID_REQUEST"})
	}

	if req.SessionID == "" || !dkgUUIDRegex.MatchString(req.SessionID) {
		return jsonResp(400, map[string]string{"error": "invalid session", "code": "INVALID_REQUEST"})
	}

	clientPubBytes, err := hex.DecodeString(req.PublicPoint)
	if err != nil {
		return jsonResp(400, map[string]string{"error": "invalid request", "code": "INVALID_REQUEST"})
	}
	clientPub, err := secp256k1.ParsePubKey(clientPubBytes)
	if err != nil {
		return jsonResp(400, map[string]string{"error": "invalid request", "code": "INVALID_REQUEST"})
	}

	if !verifySchnorrProof(clientPub, req.SessionID, req.Proof.Commitment, req.Proof.Response) {
		return jsonResp(400, map[string]string{"error": "proof verification failed", "code": "INVALID_PROOF"})
	}

	privKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return jsonResp(500, map[string]string{"error": "internal error", "code": "ENCLAVE_ERROR"})
	}
	pubKey := privKey.PubKey()

	commitHex, respHex, err := generateSchnorrProof(privKey, pubKey, req.SessionID)
	if err != nil {
		return jsonResp(500, map[string]string{"error": "internal error", "code": "ENCLAVE_ERROR"})
	}

	dkgSessionsMu.Lock()
	if len(dkgSessions) >= maxDKGSessions {
		dkgSessionsMu.Unlock()
		return jsonResp(503, map[string]string{"error": "service busy", "code": "CAPACITY_EXCEEDED"})
	}
	dkgSessions[req.SessionID] = &dkgSession{
		privateKey:      privKey,
		publicPoint:     pubKey,
		clientPublicKey: clientPub,
		createdAt:       time.Now(),
	}
	dkgSessionsMu.Unlock()

	resp := dkgRound1Response{
		PublicPoint: hex.EncodeToString(pubKey.SerializeCompressed()),
		Proof: dkgProof{
			Commitment: commitHex,
			Response:   respHex,
		},
	}

	log.Printf("DKG round1 complete for session %s", req.SessionID)
	return jsonResp(200, resp)
}

func handleDKGComplete(body string) (events.APIGatewayV2HTTPResponse, error) {
	var req dkgCompleteRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		return jsonResp(400, map[string]string{"error": "invalid JSON", "code": "INVALID_REQUEST"})
	}

	if req.SessionID == "" || !dkgUUIDRegex.MatchString(req.SessionID) {
		return jsonResp(400, map[string]string{"error": "invalid session", "code": "INVALID_REQUEST"})
	}

	dkgSessionsMu.Lock()
	sess, ok := dkgSessions[req.SessionID]
	if ok {
		delete(dkgSessions, req.SessionID)
	}
	dkgSessionsMu.Unlock()

	if !ok || time.Since(sess.createdAt) > 10*time.Minute {
		return jsonResp(400, map[string]string{"error": "invalid or expired session", "code": "SESSION_ERROR"})
	}

	jointPub := addPublicKeys(sess.clientPublicKey, sess.publicPoint)
	jointPubHex := hex.EncodeToString(jointPub.SerializeCompressed())

	if req.JointPublicKey != jointPubHex {
		return jsonResp(400, map[string]string{"error": "invalid request", "code": "INVALID_REQUEST"})
	}

	expectedHash := sha256.Sum256([]byte("DKG-CONFIRM-v1:" + req.SessionID + jointPubHex))
	expectedHashHex := hex.EncodeToString(expectedHash[:])

	if req.ConfirmationHash != expectedHashHex {
		return jsonResp(400, map[string]string{"error": "invalid request", "code": "INVALID_REQUEST"})
	}

	// Embedded mock DKG is dev-only; private key is zeroed after encoding.
	// In production, ENCLAVE_URL must be set so DKG is proxied to the enclave.
	privKeyBytes := sess.privateKey.Serialize()
	sealedShareB := hex.EncodeToString(privKeyBytes)
	for i := range privKeyBytes {
		privKeyBytes[i] = 0
	}

	resp := dkgCompleteResponse{
		JointPublicKey: jointPubHex,
		SealedShareB:   sealedShareB,
		SealMode:       "mock",
	}

	log.Printf("DKG complete for session %s — joint key: %s...", req.SessionID, jointPubHex[:16])
	return jsonResp(200, resp)
}
