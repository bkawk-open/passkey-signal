package dkg

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// --- Schnorr proof (DKG-POK-v1) ---

func GenerateSchnorrProof(privKey *secp256k1.PrivateKey, pubKey *secp256k1.PublicKey, sessionID string) (commitmentHex, responseHex string, err error) {
	k, err := RandomScalar()
	if err != nil {
		return "", "", err
	}

	var rPoint secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(k, &rPoint)
	rPoint.ToAffine()
	rPub := secp256k1.NewPublicKey(&rPoint.X, &rPoint.Y)

	e := ComputeChallenge(sessionID, pubKey, rPub)

	var xScalar secp256k1.ModNScalar
	xScalar.Set(&privKey.Key)

	var s secp256k1.ModNScalar
	s.Mul2(&xScalar, e)
	s.Negate()
	s.Add(k)

	commitmentBytes := rPub.SerializeCompressed()
	sBytes := s.Bytes()

	return hex.EncodeToString(commitmentBytes), hex.EncodeToString(sBytes[:]), nil
}

func VerifySchnorrProof(pubKey *secp256k1.PublicKey, sessionID, commitmentHex, responseHex string) bool {
	commitmentBytes, err := hex.DecodeString(commitmentHex)
	if err != nil {
		return false
	}
	responseBytes, err := hex.DecodeString(responseHex)
	if err != nil {
		return false
	}

	rPub, err := secp256k1.ParsePubKey(commitmentBytes)
	if err != nil {
		return false
	}

	var s secp256k1.ModNScalar
	if overflow := s.SetByteSlice(responseBytes); overflow {
		return false
	}

	e := ComputeChallenge(sessionID, pubKey, rPub)

	var sG, eX, result secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&s, &sG)

	var pubKeyJac secp256k1.JacobianPoint
	pubKey.AsJacobian(&pubKeyJac)
	secp256k1.ScalarMultNonConst(e, &pubKeyJac, &eX)

	secp256k1.AddNonConst(&sG, &eX, &result)
	result.ToAffine()

	var rJac secp256k1.JacobianPoint
	rPub.AsJacobian(&rJac)
	rJac.ToAffine()

	return result.X.Equals(&rJac.X) && result.Y.Equals(&rJac.Y)
}

func ComputeChallenge(sessionID string, pubKey, commitment *secp256k1.PublicKey) *secp256k1.ModNScalar {
	h := sha256.New()
	h.Write([]byte("DKG-POK-v1:"))
	// Length-prefix the session ID to prevent concatenation ambiguity
	sidBytes := []byte(sessionID)
	h.Write([]byte{byte(len(sidBytes))})
	h.Write(sidBytes)
	h.Write(pubKey.SerializeCompressed())
	h.Write(commitment.SerializeCompressed())
	digest := h.Sum(nil)

	var e secp256k1.ModNScalar
	e.SetByteSlice(digest)
	return &e
}

func RandomScalar() (*secp256k1.ModNScalar, error) {
	curveOrder := secp256k1.Params().N
	for {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		k := new(big.Int).SetBytes(b)
		if k.Sign() > 0 && k.Cmp(curveOrder) < 0 {
			var scalar secp256k1.ModNScalar
			scalar.SetByteSlice(b)
			return &scalar, nil
		}
	}
}

func AddPublicKeys(a, b *secp256k1.PublicKey) *secp256k1.PublicKey {
	var aJ, bJ, result secp256k1.JacobianPoint
	a.AsJacobian(&aJ)
	b.AsJacobian(&bJ)
	secp256k1.AddNonConst(&aJ, &bJ, &result)
	result.ToAffine()
	return secp256k1.NewPublicKey(&result.X, &result.Y)
}

