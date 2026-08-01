package envelope

import (
	"crypto/ed25519"
	"encoding/pem"
)

// PublicKeyPEMType is the PEM block type GenerateKeyPair writes and
// ParseEd25519PublicKey requires. Declared once so the reader and the writer
// cannot drift: a block carrying any other label is not this format, whatever
// its payload happens to be.
const PublicKeyPEMType = "ED25519 PUBLIC KEY"

// ParseEd25519PublicKey decodes a PEM-encoded ed25519 public key in the
// canonical format produced by GenerateKeyPair: the raw 32-byte key carried in
// a [PublicKeyPEMType] block. It is the single reader other packages use to
// turn a stored user public key back into a verifiable key, so the wire format
// lives in exactly one place alongside its writer.
//
// The block TYPE is part of the format and is checked. Accepting any 32-byte
// block would silently take an unrelated key — an X25519 public key, half an
// SSH key, the first 32 bytes of anything — as a verification key, and the only
// symptom would be a signature that never verifies, far from the paste that
// caused it.
func ParseEd25519PublicKey(publicKeyPEM PublicKeyPEM) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, ErrDecodePublicKeyPEM
	}
	if block.Type != PublicKeyPEMType {
		return nil, ErrDecodePublicKeyPEM.With(nil, "type", block.Type)
	}
	if len(block.Bytes) != ed25519.PublicKeySize {
		return nil, ErrInvalidPublicKeySize.With(nil, len(block.Bytes))
	}
	return ed25519.PublicKey(block.Bytes), nil
}
