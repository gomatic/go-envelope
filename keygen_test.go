package envelope

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- KDF Known-Answer & Parameter Tests (FR-044, threat-model-update.md) ---

// TestDeriveKey_Argon2idKnownAnswer pins deriveKey to Argon2id (RFC 9106) with
// the mandated parameters (time=1, memory=64 MiB, threads=4, keyLen=32). The
// expected key was computed INDEPENDENTLY with those literal parameters, not by
// calling deriveKey — so any drift in the kdf* constants (e.g. a memory=64-byte
// regression) or a switch from argon2id to argon2i changes the output and fails
// here, instead of passing silently behind an encrypt/decrypt round-trip.
func TestDeriveKey_Argon2idKnownAnswer(t *testing.T) {
	salt := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	const want = "f70970bc416cd587d1a54e0b10e1a910817fd152c30e372cece37e5bb66a4839"
	got := hex.EncodeToString(deriveKey("correct horse battery staple", salt))
	if got != want {
		t.Fatalf("deriveKey = %s, want %s (Argon2id time=1 mem=64MiB threads=4 len=32)", got, want)
	}
}

// TestKDFParameters guards the exact KDF parameters the spec mandates, turning
// any change into a visible failure with a clear message (defence in depth
// alongside the known-answer test).
func TestKDFParameters(t *testing.T) {
	cases := []struct {
		name      string
		got, want int
	}{
		{"time", kdfTime, 1},
		{"memory-KiB", kdfMemory, 64 * 1024},
		{"threads", kdfThreads, 4},
		{"key-length", kdfKeyLen, 32},
		{"salt-length", kdfSaltLen, 16},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("kdf %s = %d, want %d (threat-model-update.md)", c.name, c.got, c.want)
		}
	}
}

// --- Key Generation Tests ---

func TestGenerateKeyPair_Roundtrip(t *testing.T) {
	bundle, err := GenerateKeyPair("test-passphrase")
	require.NoError(t, err)
	assert.Equal(t, "ed25519", bundle.PublicKey.Type)
	assert.NotEmpty(t, bundle.PublicKey.PEM)
	assert.NotEmpty(t, bundle.PublicKey.Fingerprint)
	assert.NotEmpty(t, bundle.EncryptedPrivateKey)
	assert.NotEmpty(t, bundle.Salt)

	priv, err := DecryptPrivateKey(*bundle, "test-passphrase")
	require.NoError(t, err)
	assert.Len(t, priv, ed25519.PrivateKeySize)
}

func TestGenerateKeyPair_WrongPassphrase(t *testing.T) {
	bundle, err := GenerateKeyPair("correct-passphrase")
	require.NoError(t, err)

	_, err = DecryptPrivateKey(*bundle, "wrong-passphrase")
	assert.ErrorIs(t, err, ErrDecryptPrivateKey)
}

func TestGenerateKeyPair_FingerprintIsSHA256(t *testing.T) {
	bundle, err := GenerateKeyPair("passphrase")
	require.NoError(t, err)

	block, _ := pem.Decode([]byte(bundle.PublicKey.PEM))
	require.NotNil(t, block)

	hash := sha256.Sum256(block.Bytes)
	expected := hex.EncodeToString(hash[:])
	assert.Equal(t, expected, bundle.PublicKey.Fingerprint)
}

func TestGenerateKeyPair_DifferentKeysEachTime(t *testing.T) {
	b1, err := GenerateKeyPair("same-passphrase")
	require.NoError(t, err)
	b2, err := GenerateKeyPair("same-passphrase")
	require.NoError(t, err)
	assert.NotEqual(t, b1.PublicKey.Fingerprint, b2.PublicKey.Fingerprint)
}

func TestGenerateKeyPair_SaltRandomFails(t *testing.T) {
	withFailingRandom(t, func() {
		_, err := GenerateKeyPair("passphrase")
		assert.ErrorIs(t, err, ErrGenerateSalt)
	})
}

func TestGenerateKeyPair_Ed25519KeyGenFails(t *testing.T) {
	// ed25519.GenerateKey reads from crypto/rand.Reader directly (a crypto
	// detail we must not alter in production), so the only way to exercise the
	// ErrGenerateEd25519Key branch is to swap the package-level rand.Reader for
	// the duration of this test and restore it afterwards.
	orig := rand.Reader
	rand.Reader = failingReader{}
	defer func() { rand.Reader = orig }()

	_, err := GenerateKeyPair("passphrase")
	assert.ErrorIs(t, err, ErrGenerateEd25519Key)
}

func TestGenerateKeyPair_NonceRandomFails(t *testing.T) {
	// Let salt succeed (real randomness) but fail on the nonce by using a
	// reader that succeeds once then fails.
	orig := randReader
	randReader = &countingReader{failAfter: 1}
	defer func() { randReader = orig }()

	_, err := GenerateKeyPair("passphrase")
	assert.ErrorIs(t, err, ErrGenerateNonce)
}

func TestGenerateKeyPair_GCMConstructionFails(t *testing.T) {
	withFailingGCM(t, func() {
		_, err := GenerateKeyPair("passphrase")
		assert.ErrorIs(t, err, ErrCreateGCM)
	})
}

func TestDecryptPrivateKey_TooShort(t *testing.T) {
	bundle, err := GenerateKeyPair("passphrase")
	require.NoError(t, err)
	bundle.EncryptedPrivateKey = []byte{0x00}

	_, err = DecryptPrivateKey(*bundle, "passphrase")
	assert.ErrorIs(t, err, ErrEncryptedPrivateKeyTooShort)
}

func TestDecryptPrivateKey_GCMConstructionFails(t *testing.T) {
	bundle, err := GenerateKeyPair("passphrase")
	require.NoError(t, err)

	withFailingGCM(t, func() {
		_, err := DecryptPrivateKey(*bundle, "passphrase")
		assert.ErrorIs(t, err, ErrCreateGCM)
	})
}

// --- Key Zeroing Test ---

func TestZeroBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	zeroBytes(b)
	assert.Equal(t, []byte{0, 0, 0, 0, 0}, b)
}
