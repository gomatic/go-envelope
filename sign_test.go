package envelope

import (
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignVerify_Roundtrip(t *testing.T) {
	bundle, err := GenerateKeyPair("passphrase")
	require.NoError(t, err)

	priv, err := DecryptPrivateKey(*bundle, "passphrase")
	require.NoError(t, err)

	message := Message("hello, world")
	sig, err := Sign(message, priv)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)

	valid, err := Verify(message, sig, PublicKeyPEM(bundle.PublicKey.PEM))
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestSign_InvalidKeySize(t *testing.T) {
	_, err := Sign(Message("x"), ed25519.PrivateKey{1, 2, 3})
	assert.ErrorIs(t, err, ErrInvalidPrivateKeySize)
}

func TestSignVerify_WrongMessage(t *testing.T) {
	bundle, err := GenerateKeyPair("passphrase")
	require.NoError(t, err)
	priv, err := DecryptPrivateKey(*bundle, "passphrase")
	require.NoError(t, err)

	sig, err := Sign(Message("original"), priv)
	require.NoError(t, err)

	valid, err := Verify(Message("tampered"), sig, PublicKeyPEM(bundle.PublicKey.PEM))
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestSignVerify_WrongKey(t *testing.T) {
	b1, err := GenerateKeyPair("p1")
	require.NoError(t, err)
	b2, err := GenerateKeyPair("p2")
	require.NoError(t, err)
	priv1, err := DecryptPrivateKey(*b1, "p1")
	require.NoError(t, err)

	sig, err := Sign(Message("message"), priv1)
	require.NoError(t, err)

	valid, err := Verify(Message("message"), sig, PublicKeyPEM(b2.PublicKey.PEM))
	require.NoError(t, err)
	assert.False(t, valid)
}
