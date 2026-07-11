// Package envelope provides envelope (hybrid) encryption and signing for
// messages.
//
// Plaintext is sealed with AES-256-GCM under a per-message key that is itself
// wrapped to the recipient's RSA public key; messages are signed and verified
// with ed25519, and private keys are bundled under an Argon2id-derived key.
// Message persistence is a consumer concern — this package owns only the
// cryptography.
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
)

// rsaMinBits is the minimum accepted RSA modulus size. 2048 bits is the NIST
// SP 800-57 floor for keys protecting data past 2030; smaller keys are refused.
const rsaMinBits = 2048

// parseRSAPublicKey decodes a PEM-encoded PKIX public key and asserts it is RSA.
func parseRSAPublicKey(pemKey PublicKeyPEM) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, ErrDecodePublicKeyPEM
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, ErrParsePublicKey.With(err)
	}
	rsaPub, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, ErrNotRSAPublicKey
	}
	if rsaPub.N.BitLen() < rsaMinBits {
		return nil, ErrRSAKeyTooSmall
	}
	return rsaPub, nil
}

// sealWithAES generates a fresh AES-256 key and IV, seals the plaintext with
// AES-256-GCM, and returns the ciphertext, IV, and the (still-live) AES key.
// The caller owns zeroing the returned key.
func sealWithAES(plaintext Plaintext) (ciphertext, iv, aesKey []byte, err error) {
	aesKey = make([]byte, 32)
	if err = fillRandom(aesKey); err != nil {
		return nil, nil, nil, ErrGenerateAESKey.With(err)
	}

	gcm, err := newGCM(aesKey)
	if err != nil {
		zeroBytes(aesKey)
		return nil, nil, nil, err
	}

	iv = make([]byte, gcm.NonceSize())
	if err = fillRandom(iv); err != nil {
		zeroBytes(aesKey)
		return nil, nil, nil, ErrGenerateIV.With(err)
	}

	return gcm.Seal(nil, iv, plaintext, nil), iv, aesKey, nil
}

// newGCM constructs an AES-256-GCM AEAD from the given key. It is a package
// variable solely so tests can substitute a failing constructor to exercise
// the cipher-construction error paths in callers; production code always uses
// realNewGCM and never reassigns it.
var newGCM = realNewGCM

// gcmFromBlock wraps a block cipher in GCM. It is a package variable so tests
// can force the (otherwise unreachable for AES) GCM-construction error path;
// production always uses cipher.NewGCM.
var gcmFromBlock = cipher.NewGCM

// realNewGCM is the production AES-256-GCM AEAD constructor.
func realNewGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrCreateAESCipher.With(err)
	}
	gcm, err := gcmFromBlock(block)
	if err != nil {
		return nil, ErrCreateGCM.With(err)
	}
	return gcm, nil
}

// EncryptToRecipient performs hybrid encryption: generates a random AES-256
// key, encrypts plaintext with AES-256-GCM, then wraps the AES key with
// the recipient's RSA public key using OAEP. For ed25519 recipients,
// a shared-secret approach would be used (Phase 4 forward secrecy).
//
// SECURITY: AES key is zeroed after use. IV is unique per message.
func EncryptToRecipient(
	plaintext Plaintext,
	recipientPubKeyPEM PublicKeyPEM,
	fingerprint Fingerprint,
) (*EncryptedPayload, error) {
	rsaPub, err := parseRSAPublicKey(recipientPubKeyPEM)
	if err != nil {
		return nil, err
	}

	ciphertext, iv, aesKey, err := sealWithAES(plaintext)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(aesKey)

	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), randReader, rsaPub, aesKey, nil)
	if err != nil {
		return nil, ErrWrapAESKey.With(err)
	}

	return &EncryptedPayload{
		Ciphertext:           ciphertext,
		EncryptedKey:         encryptedKey,
		IV:                   iv,
		RecipientFingerprint: string(fingerprint),
	}, nil
}
