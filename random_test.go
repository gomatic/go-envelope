package envelope

import (
	"crypto/rand"
	"io"
	"testing"
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
