package seal

// Sealer encrypts and decrypts Share B.
// MockSealer hex-encodes (dev/test). KMSSealer uses Nitro attestation + KMS.
type Sealer interface {
	Seal(data []byte) (string, error)
	Unseal(sealed string) ([]byte, error)
	Mode() string
}
