package frost

import (
	"sync"
	"time"

	"github.com/bytemare/dkg"
	"github.com/bytemare/frost"
	"github.com/bytemare/secret-sharing/keys"
	"passkey-enclave/seal"
)

const (
	Ciphersuite     = dkg.Secp256k1
	FrostCiphersuite = frost.Secp256k1
	Threshold       = 2
	MaxSigners      = 2
	ClientID        = uint16(1)
	EnclaveID       = uint16(2)
	MaxSessions     = 1000
)

// Sealer is set by main based on whether NSM is available.
var Sealer seal.Sealer = &seal.MockSealer{}

// DKG session states
type dkgState int

const (
	dkgStateInit dkgState = iota
	dkgStateRound1Done
)

// DKGSession holds the enclave's in-memory state for a FROST DKG ceremony.
type DKGSession struct {
	participant *dkg.Participant
	r1Data      []*dkg.Round1Data // All round1 data (client + enclave)
	state       dkgState
	createdAt   time.Time
}

// SignSession holds the enclave's in-memory state for a FROST signing ceremony.
type SignSession struct {
	signer      *frost.Signer
	commitment  *frost.Commitment
	message     []byte
	createdAt   time.Time
}

var (
	dkgSessions   = make(map[string]*DKGSession)
	dkgSessionsMu sync.Mutex

	signSessions   = make(map[string]*SignSession)
	signSessionsMu sync.Mutex
)

// Request/Response types for DKG

type DKGRound1Request struct {
	SessionID       string `json:"session_id"`
	ClientR1Data    string `json:"client_r1_data"` // hex-encoded dkg.Round1Data
}

type DKGRound1Response struct {
	EnclaveR1Data string `json:"enclave_r1_data"` // hex-encoded dkg.Round1Data
}

type DKGRound2Request struct {
	SessionID       string `json:"session_id"`
	ClientR2Data    string `json:"client_r2_data"` // hex-encoded dkg.Round2Data
}

type DKGRound2Response struct {
	EnclaveR2Data string `json:"enclave_r2_data"` // hex-encoded dkg.Round2Data
}

type DKGCompleteRequest struct {
	SessionID       string `json:"session_id"`
	ClientR1Data    string `json:"client_r1_data"` // hex-encoded (needed for Finalize)
	ClientR2Data    string `json:"client_r2_data"` // hex-encoded round2 data for enclave
}

type DKGCompleteResponse struct {
	VerificationKey    string `json:"verification_key"`     // hex group public key
	EnclavePublicShare string `json:"enclave_public_share"` // hex-encoded PublicKeyShare
	SealedShareB       string `json:"sealed_share_b"`       // sealed enclave secret share
	SealMode           string `json:"seal_mode"`
	GroupCommitments   string `json:"group_commitments"`    // hex-encoded VSS commitments
	EnclaveR2Data      string `json:"enclave_r2_data"`      // hex-encoded round2 data for client
}

// Request/Response types for Signing

type SignBeginRequest struct {
	SessionID          string `json:"session_id"`
	WalletID           string `json:"wallet_id"`
	Message            string `json:"message"`               // hex-encoded message hash
	SealedShareB       string `json:"sealed_share_b"`
	SealMode           string `json:"seal_mode"`
	ConfigHex          string `json:"config_hex"`             // hex-encoded frost.Configuration
	ClientCommitment   string `json:"client_commitment"`      // hex-encoded frost.Commitment
}

type SignBeginResponse struct {
	EnclaveCommitment string `json:"enclave_commitment"` // hex-encoded frost.Commitment
}

type SignFinishRequest struct {
	SessionID           string `json:"session_id"`
	ClientSigShare      string `json:"client_sig_share"`      // hex-encoded frost.SignatureShare
	ClientCommitmentHex string `json:"client_commitment_hex"` // hex-encoded frost.Commitment
}

type SignFinishResponse struct {
	Signature string `json:"signature"` // hex-encoded frost.Signature
}

// CleanExpiredSessions removes DKG and signing sessions older than 10 minutes.
func CleanExpiredSessions() {
	dkgSessionsMu.Lock()
	for id, s := range dkgSessions {
		if time.Since(s.createdAt) > 10*time.Minute {
			delete(dkgSessions, id)
		}
	}
	dkgSessionsMu.Unlock()

	signSessionsMu.Lock()
	for id, s := range signSessions {
		if time.Since(s.createdAt) > 10*time.Minute {
			delete(signSessions, id)
		}
	}
	signSessionsMu.Unlock()
}

// KeyShareData holds what we need to reconstruct a frost.Signer from sealed storage.
type KeyShareData struct {
	Secret          []byte `json:"secret"`
	PublicKey       []byte `json:"public_key"`
	VerificationKey []byte `json:"verification_key"`
	ID              uint16 `json:"id"`
}

func newKeyShare(data KeyShareData) (*keys.KeyShare, error) {
	return frost.NewKeyShare(
		FrostCiphersuite,
		data.ID,
		data.Secret,
		data.PublicKey,
		data.VerificationKey,
	)
}
