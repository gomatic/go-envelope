package envelope

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"

	"golang.org/x/crypto/argon2"
)

const (
	kdfSaltLen = 16
	kdfTime    = 1
	kdfMemory  = 64 * 1024
	kdfThreads = 4
	kdfKeyLen  = 32
)

// deriveKey runs Argon2id over the passphrase and salt with the package KDF
// parameters. The returned key must be zeroed by the caller after use.
func deriveKey(passphrase Passphrase, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, kdfTime, kdfMemory, kdfThreads, kdfKeyLen)
}

// encryptPrivateKey seals priv under a key derived from passphrase, prefixing
// the GCM nonce to the ciphertext, and returns the freshly generated salt.
func encryptPrivateKey(priv ed25519.PrivateKey, passphrase Passphrase) (encrypted, salt []byte, err error) {
	salt = make([]byte, kdfSaltLen)
	if err = fillRandom(salt); err != nil {
		return nil, nil, ErrGenerateSalt.With(err)
	}

	derivedKey := deriveKey(passphrase, salt)
	defer zeroBytes(derivedKey)

	gcm, err := newGCM(derivedKey)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if err = fillRandom(nonce); err != nil {
		return nil, nil, ErrGenerateNonce.With(err)
	}

	privBytes := []byte(priv)
	encrypted = gcm.Seal(nonce, nonce, privBytes, nil)
	zeroBytes(privBytes)
	return encrypted, salt, nil
}

// GenerateKeyPair creates an ed25519 key pair. The private key is encrypted
// with AES-256-GCM using a key derived from the passphrase via Argon2id.
// The passphrase and derived key are zeroed after use (FR-037).
func GenerateKeyPair(passphrase Passphrase) (*KeyBundle, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, ErrGenerateEd25519Key.With(err)
	}

	encryptedPriv, salt, err := encryptPrivateKey(priv, passphrase)
	if err != nil {
		return nil, err
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PublicKeyPEMType,
		Bytes: pub,
	})

	hash := sha256.Sum256(pub)
	fingerprint := hex.EncodeToString(hash[:])

	return &KeyBundle{
		PublicKey: PublicKey{
			Type:        "ed25519",
			PEM:         string(pubPEM),
			Fingerprint: fingerprint,
		},
		EncryptedPrivateKey: encryptedPriv,
		Salt:                salt,
	}, nil
}

// DecryptPrivateKey recovers the ed25519 private key from the bundle.
// The passphrase and derived key are zeroed after use.
func DecryptPrivateKey(bundle KeyBundle, passphrase Passphrase) (ed25519.PrivateKey, error) {
	derivedKey := deriveKey(passphrase, bundle.Salt)
	defer zeroBytes(derivedKey)

	gcm, err := newGCM(derivedKey)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(bundle.EncryptedPrivateKey) < nonceSize {
		return nil, ErrEncryptedPrivateKeyTooShort
	}

	nonce := bundle.EncryptedPrivateKey[:nonceSize]
	ciphertext := bundle.EncryptedPrivateKey[nonceSize:]

	privBytes, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptPrivateKey.With(err)
	}

	return ed25519.PrivateKey(privBytes), nil
}

// zeroBytes overwrites b with zeros to scrub sensitive key material.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
