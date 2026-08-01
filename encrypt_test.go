package envelope

import (
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ecdsaKey returns a fresh P-256 ECDSA private key, used to produce a non-RSA
// key that still parses through the x509 PKIX/PKCS8 decoders.
func ecdsaKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// --- Hybrid Encryption Tests (RSA-OAEP + AES-256-GCM) ---

func generateRSAKeyPair(t *testing.T) (PublicKeyPEM, PrivateKeyPEM) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	return PublicKeyPEM(pubPEM), PrivateKeyPEM(privPEM)
}

// generateWeakRSAKeyPair builds a 1024-bit RSA key pair — below the 2048-bit
// security floor — to prove undersized keys are rejected.
func generateWeakRSAKeyPair(t *testing.T) (PublicKeyPEM, PrivateKeyPEM) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	return PublicKeyPEM(pubPEM), PrivateKeyPEM(privPEM)
}

func TestEncryptToRecipient_RejectsWeakRSAKey(t *testing.T) {
	weakPub, _ := generateWeakRSAKeyPair(t)
	_, err := EncryptToRecipient(Plaintext("secret"), weakPub, "fp")
	require.ErrorIs(t, err, ErrRSAKeyTooSmall)
}

func TestEncryptDecrypt_Roundtrip(t *testing.T) {
	pubPEM, privPEM := generateRSAKeyPair(t)
	plaintext := Plaintext("secret message for recipient")

	payload, err := EncryptToRecipient(plaintext, pubPEM, "fp-123")
	require.NoError(t, err)
	assert.NotEmpty(t, payload.Ciphertext)
	assert.NotEmpty(t, payload.EncryptedKey)
	assert.NotEmpty(t, payload.IV)
	assert.Equal(t, "fp-123", payload.RecipientFingerprint)

	decrypted, err := DecryptWithKey(*payload, privPEM)
	require.NoError(t, err)
	assert.Equal(t, []byte(plaintext), []byte(decrypted))
}

func TestEncryptDecrypt_WrongKey(t *testing.T) {
	pubPEM, _ := generateRSAKeyPair(t)
	_, wrongPrivPEM := generateRSAKeyPair(t)

	payload, err := EncryptToRecipient(Plaintext("secret"), pubPEM, "fp")
	require.NoError(t, err)

	_, err = DecryptWithKey(*payload, wrongPrivPEM)
	assert.ErrorIs(t, err, ErrUnwrapAESKey)
}

func TestEncryptDecrypt_TamperedCiphertext(t *testing.T) {
	pubPEM, privPEM := generateRSAKeyPair(t)
	payload, err := EncryptToRecipient(Plaintext("secret"), pubPEM, "fp")
	require.NoError(t, err)

	require.NotEmpty(t, payload.Ciphertext)
	payload.Ciphertext[0] ^= 0xFF

	_, err = DecryptWithKey(*payload, privPEM)
	assert.ErrorIs(t, err, ErrDecrypt)
}

func TestEncryptDecrypt_EmptyPlaintext(t *testing.T) {
	pubPEM, privPEM := generateRSAKeyPair(t)

	payload, err := EncryptToRecipient(Plaintext{}, pubPEM, "fp")
	require.NoError(t, err)

	decrypted, err := DecryptWithKey(*payload, privPEM)
	require.NoError(t, err)
	assert.Empty(t, decrypted)
}

func TestEncryptDecrypt_UniqueIVPerMessage(t *testing.T) {
	pubPEM, _ := generateRSAKeyPair(t)

	p1, err := EncryptToRecipient(Plaintext("same"), pubPEM, "fp")
	require.NoError(t, err)
	p2, err := EncryptToRecipient(Plaintext("same"), pubPEM, "fp")
	require.NoError(t, err)

	assert.NotEqual(t, p1.IV, p2.IV, "each encryption must use a unique IV")
	assert.NotEqual(t, p1.Ciphertext, p2.Ciphertext, "different IV = different ciphertext")
}

func TestEncrypt_BadPEM(t *testing.T) {
	_, err := EncryptToRecipient(Plaintext("x"), PublicKeyPEM("not pem"), "fp")
	assert.ErrorIs(t, err, ErrDecodePublicKeyPEM)
}

func TestEncrypt_UnparsablePublicKey(t *testing.T) {
	bad := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{0x00, 0x01}})
	_, err := EncryptToRecipient(Plaintext("x"), PublicKeyPEM(bad), "fp")
	assert.ErrorIs(t, err, ErrParsePublicKey)
}

func TestEncrypt_NonRSAPublicKey(t *testing.T) {
	// An ECDSA public key parses via ParsePKIXPublicKey but is not RSA.
	ecdsaPriv, err := ecdsaKey()
	require.NoError(t, err)
	pubBytes, err := x509.MarshalPKIXPublicKey(&ecdsaPriv.PublicKey)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	_, err = EncryptToRecipient(Plaintext("x"), PublicKeyPEM(pubPEM), "fp")
	assert.ErrorIs(t, err, ErrNotRSAPublicKey)
}

func TestEncrypt_AESKeyRandomFails(t *testing.T) {
	pubPEM, _ := generateRSAKeyPair(t)
	withFailingRandom(t, func() {
		_, err := EncryptToRecipient(Plaintext("x"), pubPEM, "fp")
		assert.ErrorIs(t, err, ErrGenerateAESKey)
	})
}

func TestEncrypt_WrapAESKeyFails(t *testing.T) {
	// The wrap step (rsa.EncryptOAEP) draws OAEP padding from randReader after the
	// AES key (read 1) and IV (read 2) succeed. failAfter:2 lets those two reads
	// succeed, then fails the OAEP read, exercising the wrap-failure branch.
	// (A small-modulus key can no longer reach here: the 2048-bit floor in
	// parseRSAPublicKey rejects undersized keys first.)
	pubPEM, _ := generateRSAKeyPair(t)
	orig := randReader
	randReader = &countingReader{failAfter: 2}
	defer func() { randReader = orig }()

	_, err := EncryptToRecipient(Plaintext("x"), pubPEM, "fp")
	assert.ErrorIs(t, err, ErrWrapAESKey)
}

func TestEncrypt_IVRandomFails(t *testing.T) {
	pubPEM, _ := generateRSAKeyPair(t)
	orig := randReader
	randReader = &countingReader{failAfter: 1} // AES key ok, IV fails
	defer func() { randReader = orig }()

	_, err := EncryptToRecipient(Plaintext("x"), pubPEM, "fp")
	assert.ErrorIs(t, err, ErrGenerateIV)
}

// --- GCM construction tests ---

func TestRealNewGCM_BadKeyLength(t *testing.T) {
	_, err := realNewGCM([]byte("too short"))
	assert.ErrorIs(t, err, ErrCreateAESCipher)
}

func TestRealNewGCM_GCMConstructionFails(t *testing.T) {
	orig := gcmFromBlock
	gcmFromBlock = func(cipher.Block) (cipher.AEAD, error) { return nil, io.ErrUnexpectedEOF }
	defer func() { gcmFromBlock = orig }()

	_, err := realNewGCM(make([]byte, 32))
	assert.ErrorIs(t, err, ErrCreateGCM)
}

// withFailingGCM swaps newGCM for a constructor that always errors.
func withFailingGCM(t *testing.T, fn func()) {
	t.Helper()
	orig := newGCM
	newGCM = func([]byte) (cipher.AEAD, error) { return nil, ErrCreateGCM }
	defer func() { newGCM = orig }()
	fn()
}

func TestEncrypt_GCMConstructionFails(t *testing.T) {
	pubPEM, _ := generateRSAKeyPair(t)
	withFailingGCM(t, func() {
		_, err := EncryptToRecipient(Plaintext("x"), pubPEM, "fp")
		assert.ErrorIs(t, err, ErrCreateGCM)
	})
}

// TestGcmFromBlockIsCipherNewGCMInProduction names gcmFromBlock's claim. Like
// newGCM it is a variable only so a test can force the GCM-construction error
// path, which AES can never trigger. If production ever read a substituted
// constructor, every envelope would be sealed with whatever AEAD that returned
// — and the ciphertext would still round-trip through this package's own
// decrypt, so no functional test would notice.
func TestGcmFromBlockIsCipherNewGCMInProduction(t *testing.T) {
	assert.Equal(t,
		reflect.ValueOf(cipher.NewGCM).Pointer(),
		reflect.ValueOf(gcmFromBlock).Pointer(),
		"gcmFromBlock must be cipher.NewGCM itself in production")
	assert.Equal(t,
		reflect.ValueOf(realNewGCM).Pointer(),
		reflect.ValueOf(newGCM).Pointer(),
		"newGCM must be the real AES-256-GCM constructor in production")
}

// TestRealNewGCMProducesAES256GCM pins what the production constructor actually
// builds. AES-256 is a key-length property, and GCM is the only mode here that
// authenticates — a construction that silently produced AES-128 or an
// unauthenticated mode would encrypt and decrypt perfectly while providing far
// less than the package claims.
func TestRealNewGCMProducesAES256GCM(t *testing.T) {
	key := make([]byte, 32)
	aead, err := realNewGCM(key)

	require.NoError(t, err)
	assert.Equal(t, 12, aead.NonceSize(), "GCM's standard nonce size")
	assert.Equal(t, 16, aead.Overhead(), "GCM's 128-bit authentication tag")

	_, err = realNewGCM(make([]byte, 16))
	assert.NoError(t, err, "the constructor itself accepts any valid AES size")

	_, err = realNewGCM(make([]byte, 7))
	assert.ErrorIs(t, err, ErrCreateAESCipher, "an invalid key length is a matchable failure")
}
