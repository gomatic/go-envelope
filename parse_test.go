package envelope

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseEd25519PublicKeyRoundTripsTheCanonicalFormat names
// ParseEd25519PublicKey's claim to be the single reader for the format
// GenerateKeyPair writes. The round-trip is the contract: whatever the writer
// emits, this reader must accept and return byte-identical, or a stored key
// becomes unreadable by the package that stored it.
func TestParseEd25519PublicKeyRoundTripsTheCanonicalFormat(t *testing.T) {
	t.Parallel()

	bundle, err := GenerateKeyPair("passphrase")
	require.NoError(t, err)

	parsed, err := ParseEd25519PublicKey(PublicKeyPEM(bundle.PublicKey.PEM))

	require.NoError(t, err)
	assert.Len(t, parsed, ed25519.PublicKeySize)
	assert.Equal(t, bundle.PublicKey.Fingerprint, fingerprintOf(parsed),
		"the key that comes back must be the key that was written")
}

// TestPublicKeyPEMTypeIsSharedByTheReaderAndTheWriter names PublicKeyPEMType's
// claim. Reader and writer drifting apart is the failure it exists to prevent:
// a writer emitting one label and a reader requiring another makes every stored
// key unreadable, and the constant is what makes that a compile-time
// impossibility rather than a convention.
func TestPublicKeyPEMTypeIsSharedByTheReaderAndTheWriter(t *testing.T) {
	t.Parallel()

	bundle, err := GenerateKeyPair("passphrase")
	require.NoError(t, err)

	block, _ := pem.Decode([]byte(bundle.PublicKey.PEM))
	require.NotNil(t, block)
	assert.Equal(t, PublicKeyPEMType, block.Type,
		"the writer must emit exactly the type the reader requires")
}

// fingerprintOf is the SHA-256 hex digest GenerateKeyPair records, recomputed
// so the round-trip is checked against the stored identity rather than against
// itself.
func fingerprintOf(key ed25519.PublicKey) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])
}

// TestParseEd25519PublicKeyRequiresTheBlockType pins the type check. Every
// input below carries a payload of exactly the right length, so length alone
// cannot tell them apart — only the label does. Without the check, an X25519
// public key, the first 32 bytes of an SSH key, or any other 32-byte blob is
// accepted as a VERIFICATION key, and the only symptom is a signature that
// never verifies, arbitrarily far from the paste that caused it.
func TestParseEd25519PublicKeyRequiresTheBlockType(t *testing.T) {
	t.Parallel()
	raw := make([]byte, ed25519.PublicKeySize)

	for _, blockType := range []string{
		"X25519 PUBLIC KEY",
		"PUBLIC KEY",
		"RSA PUBLIC KEY",
		"OPENSSH PRIVATE KEY",
		"",
	} {
		encoded := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: raw})

		_, err := ParseEd25519PublicKey(PublicKeyPEM(encoded))

		assert.ErrorIs(t, err, ErrDecodePublicKeyPEM,
			"a %q block is not an ed25519 public key, whatever its payload length", blockType)
	}

	right := pem.EncodeToMemory(&pem.Block{Type: PublicKeyPEMType, Bytes: raw})
	_, err := ParseEd25519PublicKey(PublicKeyPEM(right))
	assert.NoError(t, err, "the declared type must still be accepted, or the check rejects everything")
}

// TestParseEd25519PublicKeyRejectsAWrongSizedKey pins the length check with a
// distinguishable sentinel, so a caller can tell "this is not PEM / not our
// format" from "this is our format but the key is malformed".
func TestParseEd25519PublicKeyRejectsAWrongSizedKey(t *testing.T) {
	t.Parallel()

	for _, size := range []int{0, 1, ed25519.PublicKeySize - 1, ed25519.PublicKeySize + 1, 64} {
		encoded := pem.EncodeToMemory(&pem.Block{Type: PublicKeyPEMType, Bytes: make([]byte, size)})

		_, err := ParseEd25519PublicKey(PublicKeyPEM(encoded))

		assert.ErrorIs(t, err, ErrInvalidPublicKeySize, "%d bytes is not an ed25519 public key", size)
	}
}

// TestParseEd25519PublicKeyRejectsAnythingThatIsNotPEM covers the decode
// failure. pem.Decode returns nil for input carrying no block, and returning a
// key for it would mean parsing succeeded on arbitrary bytes.
func TestParseEd25519PublicKeyRejectsAnythingThatIsNotPEM(t *testing.T) {
	t.Parallel()

	for _, input := range []PublicKeyPEM{
		"",
		"not pem at all",
		"-----BEGIN ED25519 PUBLIC KEY-----\nno end marker\n",
		"-----BEGIN ED25519 PUBLIC KEY-----\n!!!not base64!!!\n-----END ED25519 PUBLIC KEY-----\n",
	} {
		_, err := ParseEd25519PublicKey(input)
		assert.ErrorIs(t, err, ErrDecodePublicKeyPEM, "input %q is not a PEM block", input)
	}
}
