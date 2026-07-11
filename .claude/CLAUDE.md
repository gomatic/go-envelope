# go-envelope

Envelope (hybrid) encryption and signing (package `envelope`): RSA + ed25519 key generation with Argon2id-protected `KeyBundle`s, `Sign`/`Verify`, `EncryptToRecipient`/`DecryptWithKey` (AES-256-GCM per-message key wrapped to the recipient's RSA public key), crypto-safe randoms, and PEM key parsing. Message persistence is a consumer concern. Generic — lives in `gomatic`; extracted from xto-email's `go-encryption` crypto core during the xto repo split (see `xto-email/_projects/specs/repo-split/`); the pg-backed message store stayed with `xtod`.

- Library repo (`library.go` marker); flat single-package layout at the root; deps: golang.org/x/crypto (argon2), `gomatic/go-error` (sentinels), testify for tests. Distinct from `go-cry` (age/SSH stream encryption).
- Gate: shared Makefile from `nicerobot/tools.repository` — gofumpt, vet, staticcheck, golangci-lint, govulncheck, gocognit ≤ 7, 100% coverage. Never edit the distributed `Makefile`/`.golangci.yaml`/`.github` in-tree.
- Public docs live in `docs.go-envelope`; the README is exactly badges + the docs link.
