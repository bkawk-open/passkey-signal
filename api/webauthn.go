package main

import (
	"github.com/go-webauthn/webauthn/webauthn"
)

func newWebAuthn() (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPID:          "passkey-signal.bkawk.com",
		RPDisplayName: "Passkey DKG",
		RPOrigins:     []string{"https://passkey-signal.bkawk.com"},
	})
}
