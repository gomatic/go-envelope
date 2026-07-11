package envelope

import (
	"crypto/ed25519"
	"encoding/pem"
)

// ParseEd25519PublicKey decodes a PEM-encoded ed25519 public key in the
// canonical format produced by GenerateKeyPair: the raw 32-byte key carried in
// a PEM block (the "ED25519 PUBLIC KEY" type). It is the single reader other
// packages use to turn a stored user public key back into a verifiable key, so
// the wire format lives in exactly one place alongside its writer.
func ParseEd25519PublicKey(publicKeyPEM PublicKeyPEM) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, ErrDecodePublicKeyPEM
	}
	if len(block.Bytes) != ed25519.PublicKeySize {
		return nil, ErrInvalidPublicKeySize.With(nil, len(block.Bytes))
	}
	return ed25519.PublicKey(block.Bytes), nil
}
