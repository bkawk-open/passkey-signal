package frost

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"time"

	"github.com/bytemare/frost"
)

// HandleSignBegin processes the client's commitment and returns the enclave's commitment.
func HandleSignBegin(req SignBeginRequest) (int, interface{}) {
	if req.SessionID == "" {
		return 400, map[string]string{"error": "invalid session", "code": "INVALID_REQUEST"}
	}

	// Decode message hash
	message, err := hex.DecodeString(req.Message)
	if err != nil || len(message) == 0 {
		return 400, map[string]string{"error": "invalid message", "code": "INVALID_REQUEST"}
	}

	// Unseal the enclave's key share
	sealedBytes, err := Sealer.Unseal(req.SealedShareB)
	if err != nil {
		log.Printf("FROST sign: unseal error: %v", err)
		return 500, map[string]string{"error": "unseal failed", "code": "ENCLAVE_ERROR"}
	}

	var ksData KeyShareData
	if err := json.Unmarshal(sealedBytes, &ksData); err != nil {
		log.Printf("FROST sign: invalid key share data: %v", err)
		return 500, map[string]string{"error": "invalid key share", "code": "ENCLAVE_ERROR"}
	}

	keyShare, err := newKeyShare(ksData)
	if err != nil {
		log.Printf("FROST sign: failed to reconstruct key share: %v", err)
		return 500, map[string]string{"error": "internal error", "code": "ENCLAVE_ERROR"}
	}

	// Decode frost configuration
	var config frost.Configuration
	if err := config.DecodeHex(req.ConfigHex); err != nil {
		log.Printf("FROST sign: failed to decode config: %v", err)
		return 400, map[string]string{"error": "invalid config", "code": "INVALID_REQUEST"}
	}
	if err := config.Init(); err != nil {
		log.Printf("FROST sign: failed to init config: %v", err)
		return 400, map[string]string{"error": "invalid config", "code": "INVALID_REQUEST"}
	}

	// Create signer from key share
	signer, err := config.Signer(keyShare)
	if err != nil {
		log.Printf("FROST sign: failed to create signer: %v", err)
		return 500, map[string]string{"error": "internal error", "code": "ENCLAVE_ERROR"}
	}

	// Generate enclave's commitment
	commitment := signer.Commit()
	commitmentHex := commitment.Hex()

	// Decode client's commitment
	var clientCommitment frost.Commitment
	if err := clientCommitment.DecodeHex(req.ClientCommitment); err != nil {
		log.Printf("FROST sign: invalid client commitment: %v", err)
		return 400, map[string]string{"error": "invalid client_commitment", "code": "INVALID_REQUEST"}
	}

	// Store signing session
	signSessionsMu.Lock()
	if len(signSessions) >= MaxSessions {
		signSessionsMu.Unlock()
		return 503, map[string]string{"error": "service busy", "code": "CAPACITY_EXCEEDED"}
	}
	signSessions[req.SessionID] = &SignSession{
		signer:     signer,
		commitment: commitment,
		message:    message,
		createdAt:  time.Now(),
	}
	signSessionsMu.Unlock()

	log.Printf("FROST sign begin for session %s", req.SessionID)
	return 200, SignBeginResponse{
		EnclaveCommitment: commitmentHex,
	}
}

// HandleSignFinish computes the enclave's signature share, aggregates with client's, returns final signature.
func HandleSignFinish(req SignFinishRequest) (int, interface{}) {
	if req.SessionID == "" {
		return 400, map[string]string{"error": "invalid session", "code": "INVALID_REQUEST"}
	}

	signSessionsMu.Lock()
	sess, ok := signSessions[req.SessionID]
	if ok {
		delete(signSessions, req.SessionID)
	}
	signSessionsMu.Unlock()

	if !ok {
		return 400, map[string]string{"error": "invalid or expired session", "code": "SESSION_ERROR"}
	}
	if time.Since(sess.createdAt) > 10*time.Minute {
		return 400, map[string]string{"error": "session expired", "code": "SESSION_ERROR"}
	}

	// Decode client's signature share
	var clientSigShare frost.SignatureShare
	if err := clientSigShare.DecodeHex(req.ClientSigShare); err != nil {
		log.Printf("FROST sign: invalid client sig share: %v", err)
		return 400, map[string]string{"error": "invalid client_sig_share", "code": "INVALID_REQUEST"}
	}

	// Build commitment list (client + enclave)
	var clientCommitment frost.Commitment
	if err := clientCommitment.DecodeHex(req.ClientCommitmentHex); err != nil {
		log.Printf("FROST sign: invalid client commitment: %v", err)
		return 400, map[string]string{"error": "invalid client_commitment", "code": "INVALID_REQUEST"}
	}
	commitments := frost.CommitmentList{&clientCommitment, sess.commitment}
	commitments.Sort()

	// Enclave computes its signature share
	enclaveSigShare, err := sess.signer.Sign(sess.message, commitments)
	if err != nil {
		log.Printf("FROST sign: enclave sign failed: %v", err)
		return 500, map[string]string{"error": "signing failed", "code": "ENCLAVE_ERROR"}
	}

	// Aggregate signature shares
	signature, err := sess.signer.Configuration.AggregateSignatures(
		sess.message,
		[]*frost.SignatureShare{&clientSigShare, enclaveSigShare},
		commitments,
		true, // verify each share
	)
	if err != nil {
		log.Printf("FROST sign: aggregation failed: %v", err)
		return 500, map[string]string{"error": "signature aggregation failed", "code": "ENCLAVE_ERROR"}
	}

	sigHex := signature.Hex()
	log.Printf("FROST sign complete for session %s", req.SessionID)
	return 200, SignFinishResponse{
		Signature: sigHex,
	}
}
