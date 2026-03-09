package frost

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"time"

	"github.com/bytemare/dkg"
)

// HandleDKGRound1 processes the client's round 1 data and returns the enclave's round 1 data.
func HandleDKGRound1(req DKGRound1Request) (int, interface{}) {
	if req.SessionID == "" {
		return 400, map[string]string{"error": "invalid session", "code": "INVALID_REQUEST"}
	}

	// Decode client's Round1Data
	clientR1Bytes, err := hex.DecodeString(req.ClientR1Data)
	if err != nil {
		return 400, map[string]string{"error": "invalid client_r1_data", "code": "INVALID_REQUEST"}
	}
	var clientR1 dkg.Round1Data
	if err := clientR1.Decode(clientR1Bytes); err != nil {
		return 400, map[string]string{"error": "invalid client_r1_data encoding", "code": "INVALID_REQUEST"}
	}

	// Create enclave's DKG participant (ID=2)
	participant, err := Ciphersuite.NewParticipant(EnclaveID, Threshold, MaxSigners)
	if err != nil {
		log.Printf("FROST DKG: failed to create participant: %v", err)
		return 500, map[string]string{"error": "internal error", "code": "ENCLAVE_ERROR"}
	}

	// Generate enclave's round 1 data
	enclaveR1 := participant.Start()
	enclaveR1Hex := hex.EncodeToString(enclaveR1.Encode())

	// Store session
	dkgSessionsMu.Lock()
	if len(dkgSessions) >= MaxSessions {
		dkgSessionsMu.Unlock()
		return 503, map[string]string{"error": "service busy", "code": "CAPACITY_EXCEEDED"}
	}
	dkgSessions[req.SessionID] = &DKGSession{
		participant: participant,
		r1Data:      []*dkg.Round1Data{&clientR1, enclaveR1},
		state:       dkgStateRound1Done,
		createdAt:   time.Now(),
	}
	dkgSessionsMu.Unlock()

	log.Printf("FROST DKG round1 complete for session %s", req.SessionID)
	return 200, DKGRound1Response{
		EnclaveR1Data: enclaveR1Hex,
	}
}

// HandleDKGComplete processes round 2 and finalizes the DKG ceremony.
// The client sends its round2 data for the enclave. The enclave sends back its
// round2 data for the client, plus the sealed enclave key share.
func HandleDKGComplete(req DKGCompleteRequest) (int, interface{}) {
	if req.SessionID == "" {
		return 400, map[string]string{"error": "invalid session", "code": "INVALID_REQUEST"}
	}

	dkgSessionsMu.Lock()
	sess, ok := dkgSessions[req.SessionID]
	if ok {
		delete(dkgSessions, req.SessionID)
	}
	dkgSessionsMu.Unlock()

	if !ok {
		return 400, map[string]string{"error": "invalid or expired session", "code": "SESSION_ERROR"}
	}
	if time.Since(sess.createdAt) > 10*time.Minute {
		return 400, map[string]string{"error": "session expired", "code": "SESSION_ERROR"}
	}
	if sess.state != dkgStateRound1Done {
		return 400, map[string]string{"error": "invalid session state", "code": "SESSION_ERROR"}
	}

	// Decode client's round 2 data for the enclave
	clientR2Bytes, err := hex.DecodeString(req.ClientR2Data)
	if err != nil {
		return 400, map[string]string{"error": "invalid client_r2_data", "code": "INVALID_REQUEST"}
	}
	var clientR2ForEnclave dkg.Round2Data
	if err := clientR2ForEnclave.Decode(clientR2Bytes); err != nil {
		return 400, map[string]string{"error": "invalid client_r2_data encoding", "code": "INVALID_REQUEST"}
	}

	// Enclave computes its round 2 data
	enclaveR2Map, err := sess.participant.Continue(sess.r1Data)
	if err != nil {
		log.Printf("FROST DKG round2 failed: %v", err)
		return 500, map[string]string{"error": "DKG round2 failed", "code": "ENCLAVE_ERROR"}
	}

	// Get enclave's round2 data destined for the client (ID=1)
	enclaveR2ForClient, ok := enclaveR2Map[ClientID]
	if !ok {
		log.Printf("FROST DKG: no round2 data for client")
		return 500, map[string]string{"error": "internal error", "code": "ENCLAVE_ERROR"}
	}
	enclaveR2Hex := hex.EncodeToString(enclaveR2ForClient.Encode())

	// Finalize enclave's key share
	enclaveKeyShare, err := sess.participant.Finalize(
		sess.r1Data,
		[]*dkg.Round2Data{&clientR2ForEnclave},
	)
	if err != nil {
		log.Printf("FROST DKG finalize failed: %v", err)
		return 500, map[string]string{"error": "DKG finalize failed", "code": "ENCLAVE_ERROR"}
	}

	// Compute verification key from round 1 commitments
	verificationKey, err := dkg.VerificationKeyFromRound1(Ciphersuite, sess.r1Data)
	if err != nil {
		log.Printf("FROST DKG: failed to compute verification key: %v", err)
		return 500, map[string]string{"error": "internal error", "code": "ENCLAVE_ERROR"}
	}

	// Serialize the key share data for sealing
	ksData := KeyShareData{
		Secret:          enclaveKeyShare.Secret.Encode(),
		PublicKey:       enclaveKeyShare.PublicKeyShare.PublicKey.Encode(),
		VerificationKey: verificationKey.Encode(),
		ID:              EnclaveID,
	}
	ksJSON, err := json.Marshal(ksData)
	if err != nil {
		log.Printf("FROST DKG: failed to marshal key share: %v", err)
		return 500, map[string]string{"error": "internal error", "code": "ENCLAVE_ERROR"}
	}

	// Seal the enclave's key share
	sealedShare, err := Sealer.Seal(ksJSON)
	if err != nil {
		log.Printf("FROST DKG: seal error: %v", err)
		return 500, map[string]string{"error": "seal failed", "code": "ENCLAVE_ERROR"}
	}

	// Encode public key share for the response
	pubShareHex := hex.EncodeToString(enclaveKeyShare.PublicKeyShare.Encode())

	// Encode VSS commitments for storage
	var commitments [][]byte
	for _, r1 := range sess.r1Data {
		for _, c := range r1.Commitment {
			commitments = append(commitments, c.Encode())
		}
	}
	commitmentsJSON, _ := json.Marshal(commitments)

	vkHex := hex.EncodeToString(verificationKey.Encode())
	log.Printf("FROST DKG complete for session %s — verification key: %s...", req.SessionID, vkHex[:min(32, len(vkHex))])

	return 200, DKGCompleteResponse{
		VerificationKey:    vkHex,
		EnclavePublicShare: pubShareHex,
		SealedShareB:       sealedShare,
		SealMode:           Sealer.Mode(),
		GroupCommitments:   hex.EncodeToString(commitmentsJSON),
		EnclaveR2Data:      enclaveR2Hex,
	}
}
