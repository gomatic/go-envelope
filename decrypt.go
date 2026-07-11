package envelope

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
)

// parseRSAPrivateKey decodes a PEM-encoded PKCS#8 private key and asserts it is RSA.
func parseRSAPrivateKey(pemKey PrivateKeyPEM) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, ErrDecodePrivateKeyPEM
	}
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, ErrParsePrivateKey.With(err)
	}
	rsaPriv, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrNotRSAPrivateKey
	}
	if rsaPriv.N.BitLen() < rsaMinBits {
		return nil, ErrRSAKeyTooSmall
	}
	return rsaPriv, nil
}

// DecryptWithKey decrypts an EncryptedPayload using the recipient's RSA
// private key. The AES key is unwrapped via RSA-OAEP, then used to
// decrypt the ciphertext with AES-256-GCM.
//
// SECURITY: AES key is zeroed after use. GCM auth tag validates integrity.
func DecryptWithKey(payload EncryptedPayload, privateKeyPEM PrivateKeyPEM) (Plaintext, error) {
	rsaPriv, err := parseRSAPrivateKey(privateKeyPEM)
	if err != nil {
		return nil, err
	}

	aesKey, err := rsa.DecryptOAEP(sha256.New(), nil, rsaPriv, payload.EncryptedKey, nil)
	if err != nil {
		return nil, ErrUnwrapAESKey.With(err)
	}
	defer zeroBytes(aesKey)

	gcm, err := newGCM(aesKey)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, payload.IV, payload.Ciphertext, nil)
	if err != nil {
		return nil, ErrDecrypt.With(err)
	}

	return plaintext, nil
}
