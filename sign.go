package envelope

import (
	"crypto/ed25519"
)

// Sign creates an ed25519 signature over the message using the private key.
func Sign(message Message, privateKey ed25519.PrivateKey) (Signature, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidPrivateKeySize.With(nil, len(privateKey))
	}
	return ed25519.Sign(privateKey, message), nil
}
