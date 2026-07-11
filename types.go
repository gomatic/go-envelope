package envelope

// Plaintext is the unencrypted message body handed to EncryptToRecipient and
// recovered by DecryptWithKey.
type Plaintext []byte

// PublicKeyPEM is a PEM-encoded public key.
type PublicKeyPEM string

// PrivateKeyPEM is a PEM-encoded private key.
type PrivateKeyPEM string

// Fingerprint identifies a recipient key (SHA-256 hex of the public key).
type Fingerprint string

// Message is the byte payload signed by Sign and checked by Verify.
type Message []byte

// Signature is an ed25519 signature produced by Sign.
type Signature []byte

// Passphrase protects a private key bundle via the Argon2id KDF.
type Passphrase string

type PublicKey struct {
	Type        string `json:"type"`
	PEM         string `json:"pem"`
	Fingerprint string `json:"fingerprint"`
}

type EncryptedPayload struct {
	RecipientFingerprint string `json:"recipient_fingerprint"`
	Ciphertext           []byte `json:"ciphertext"`
	EncryptedKey         []byte `json:"encrypted_key"`
	IV                   []byte `json:"iv"`
}

type KeyBundle struct {
	PublicKey           PublicKey `json:"public_key"`
	EncryptedPrivateKey []byte    `json:"encrypted_private_key"`
	Salt                []byte    `json:"salt"`
}
