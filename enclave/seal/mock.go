package seal

import "encoding/hex"

// MockSealer stores Share B as plaintext hex. For development only.
type MockSealer struct{}

func (m *MockSealer) Seal(data []byte) (string, error) {
	return hex.EncodeToString(data), nil
}

func (m *MockSealer) Unseal(sealed string) ([]byte, error) {
	return hex.DecodeString(sealed)
}

func (m *MockSealer) Mode() string { return "mock" }
