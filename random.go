package envelope

import (
	"crypto/rand"
	"io"
)

// randReader is the source of cryptographic randomness used to fill key, IV,
// salt, and nonce buffers. It is a package-level variable solely so tests can
// inject a failing reader to exercise the generation error paths; production
// code always uses crypto/rand.Reader and never reassigns it.
//
// It is an io.Reader (an external signature), so it is intentionally left as
// that interface rather than wrapped in a named type.
var randReader = rand.Reader

// fillRandom fills b with cryptographic randomness from the injected reader.
// It uses io.ReadFull to match the semantics of the original crypto/rand.Read
// calls this replaced.
func fillRandom(b []byte) error {
	_, err := io.ReadFull(randReader, b)
	return err
}
