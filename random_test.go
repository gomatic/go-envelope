package envelope

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingReader is an io.Reader that always returns an error, used to drive the
// randomness-generation error paths.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// withFailingRandom swaps randReader for a failing reader for the duration of fn.
func withFailingRandom(t *testing.T, fn func()) {
	t.Helper()
	orig := randReader
	randReader = failingReader{}
	defer func() { randReader = orig }()
	fn()
}

// countingReader fills buffers with real randomness for the first failAfter
// reads, then returns an error. Used to target a specific generation step.
type countingReader struct {
	calls     int
	failAfter int
}

func (c *countingReader) Read(b []byte) (int, error) {
	c.calls++
	if c.calls > c.failAfter {
		return 0, io.ErrUnexpectedEOF
	}
	return rand.Read(b)
}

// TestRandReaderIsCryptoRandInProduction names randReader's claim. It exists as
// a package variable ONLY so a test can inject a failing reader; the moment
// production reads from anything but crypto/rand.Reader, every key, IV, salt
// and nonce this package generates becomes predictable, and no test of the
// encryption itself would notice — ciphertext from a weak key still decrypts.
//
// The default is asserted by identity, not by behaviour, because behaviour
// cannot distinguish a CSPRNG from a well-seeded weak one.
func TestRandReaderIsCryptoRandInProduction(t *testing.T) {
	assert.Equal(t, rand.Reader, randReader,
		"the default randomness source must be crypto/rand.Reader itself")
}

// TestFillRandomRequiresTheFullBufferAndSurfacesAShortRead names fillRandom's
// contract. io.ReadFull is the whole point: a plain Read may return fewer bytes
// than asked for, and accepting a short read would leave the tail of a key,
// nonce or salt as zeroes — a catastrophic, silent weakening that produces
// perfectly valid-looking ciphertext.
func TestFillRandomRequiresTheFullBufferAndSurfacesAShortRead(t *testing.T) {
	orig := randReader
	defer func() { randReader = orig }()

	// A reader that yields one byte per call must still fill the whole buffer.
	randReader = iotest.OneByteReader(rand.Reader)
	buf := make([]byte, 32)
	require.NoError(t, fillRandom(buf))
	assert.NotEqual(t, make([]byte, 32), buf, "every byte must have been written")

	// A reader that ends early must be an error, never a partially-filled buffer.
	randReader = bytes.NewReader([]byte{1, 2, 3})
	short := make([]byte, 32)
	err := fillRandom(short)
	require.Error(t, err, "a short read must not be accepted as a filled buffer")
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}
