package envelope

import (
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerify_BadPEM(t *testing.T) {
	valid, err := Verify(Message("m"), Signature("s"), PublicKeyPEM("not pem"))
	assert.False(t, valid)
	assert.ErrorIs(t, err, ErrDecodePublicKeyPEM)
}

func TestVerify_WrongPublicKeySize(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "ED25519 PUBLIC KEY", Bytes: []byte{1, 2, 3}})
	valid, err := Verify(Message("m"), Signature("s"), PublicKeyPEM(pemBytes))
	assert.False(t, valid)
	assert.ErrorIs(t, err, ErrInvalidPublicKeySize)
}
