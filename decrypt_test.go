package envelope

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecryptWithKey_RejectsWeakRSAKey(t *testing.T) {
	_, weakPriv := generateWeakRSAKeyPair(t)
	_, err := DecryptWithKey(EncryptedPayload{}, weakPriv)
	require.ErrorIs(t, err, ErrRSAKeyTooSmall)
}

func TestDecrypt_BadPEM(t *testing.T) {
	_, err := DecryptWithKey(EncryptedPayload{}, PrivateKeyPEM("not pem"))
	assert.ErrorIs(t, err, ErrDecodePrivateKeyPEM)
}

func TestDecrypt_UnparsablePrivateKey(t *testing.T) {
	bad := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0x00, 0x01}})
	_, err := DecryptWithKey(EncryptedPayload{}, PrivateKeyPEM(bad))
	assert.ErrorIs(t, err, ErrParsePrivateKey)
}

func TestDecrypt_NonRSAPrivateKey(t *testing.T) {
	ecdsaPriv, err := ecdsaKey()
	require.NoError(t, err)
	privBytes, err := x509.MarshalPKCS8PrivateKey(ecdsaPriv)
	require.NoError(t, err)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	_, err = DecryptWithKey(EncryptedPayload{}, PrivateKeyPEM(privPEM))
	assert.ErrorIs(t, err, ErrNotRSAPrivateKey)
}

func TestDecrypt_GCMConstructionFails(t *testing.T) {
	pubPEM, privPEM := generateRSAKeyPair(t)
	payload, err := EncryptToRecipient(Plaintext("x"), pubPEM, "fp")
	require.NoError(t, err)

	withFailingGCM(t, func() {
		_, err := DecryptWithKey(*payload, privPEM)
		assert.ErrorIs(t, err, ErrCreateGCM)
	})
}
