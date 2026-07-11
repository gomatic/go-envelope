package envelope

import errs "github.com/gomatic/go-error"

// Sentinel errors this package emits, matchable with errors.Is. The Const
// mechanism is owned by gomatic/go-error. Keep sorted alphabetically.
const (
	ErrCreateAESCipher             errs.Const = "creating AES cipher"
	ErrCreateGCM                   errs.Const = "creating GCM"
	ErrDecodePrivateKeyPEM         errs.Const = "failed to decode PEM private key"
	ErrDecodePublicKeyPEM          errs.Const = "failed to decode PEM public key"
	ErrDecrypt                     errs.Const = "decrypting"
	ErrDecryptPrivateKey           errs.Const = "decrypting private key"
	ErrEncryptedPrivateKeyTooShort errs.Const = "encrypted private key too short"
	ErrGenerateAESKey              errs.Const = "generating AES key"
	ErrGenerateEd25519Key          errs.Const = "generating ed25519 key"
	ErrGenerateIV                  errs.Const = "generating IV"
	ErrGenerateNonce               errs.Const = "generating nonce"
	ErrGenerateSalt                errs.Const = "generating salt"
	ErrInvalidPrivateKeySize       errs.Const = "invalid private key size"
	ErrInvalidPublicKeySize        errs.Const = "invalid public key size"
	ErrNotRSAPrivateKey            errs.Const = "private key is not RSA"
	ErrNotRSAPublicKey             errs.Const = "public key is not RSA"
	ErrParsePrivateKey             errs.Const = "parsing private key"
	ErrParsePublicKey              errs.Const = "parsing public key"
	ErrRSAKeyTooSmall              errs.Const = "RSA key is smaller than the 2048-bit minimum"
	ErrUnwrapAESKey                errs.Const = "unwrapping AES key"
	ErrWrapAESKey                  errs.Const = "wrapping AES key"
)
