package dkg

import (
	"sync"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"passkey-enclave/seal"
)

type Round1Request struct {
	SessionID   string `json:"session_id"`
	PublicPoint string `json:"public_point"`
	Proof       Proof  `json:"proof"`
}

type Proof struct {
	Commitment string `json:"commitment"`
	Response   string `json:"response"`
}

type Round1Response struct {
	PublicPoint string `json:"public_point"`
	Proof       Proof  `json:"proof"`
}

type CompleteRequest struct {
	SessionID        string `json:"session_id"`
	JointPublicKey   string `json:"joint_public_key"`
	ConfirmationHash string `json:"confirmation_hash"`
}

type CompleteResponse struct {
	JointPublicKey string `json:"joint_public_key"`
	SealedShareB   string `json:"sealed_share_b"`
	SealMode       string `json:"seal_mode"`
}

type session struct {
	privateKey      *secp256k1.PrivateKey
	publicPoint     *secp256k1.PublicKey
	clientPublicKey *secp256k1.PublicKey
	createdAt       time.Time
}

const maxSessions = 1000

var (
	sessions   = make(map[string]*session)
	sessionsMu sync.Mutex

	// Sealer is set by main based on whether NSM is available.
	Sealer seal.Sealer = &seal.MockSealer{}
)

func CleanExpiredSessions() {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	for id, s := range sessions {
		if time.Since(s.createdAt) > 10*time.Minute {
			delete(sessions, id)
		}
	}
}
