package envelope

import (
	"crypto/ed25519"
)

// Verify checks an ed25519 signature against the message and public key PEM.
func Verify(message Message, signature Signature, publicKeyPEM PublicKeyPEM) (bool, error) {
	pub, err := ParseEd25519PublicKey(publicKeyPEM)
	if err != nil {
		return false, err
	}
	return ed25519.Verify(pub, message, signature), nil
}
