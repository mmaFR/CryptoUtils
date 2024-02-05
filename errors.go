package CryptoUtils

import (
	"errors"
)

var ErrRsaKeyPairNotInitialized error = errors.New("rsa key pair not yet initialized")
var ErrUnknownKeyType error = errors.New("unknown key type")
var ErrPrivateKeyNotSet error = errors.New("the private is not yet set")

var ErrEcdsaNotSupported error = errors.New("ecdsa key is not supported for decryption/encryption")
var ErrEd25519NotSupported error = errors.New("ed25519 key is not supported for decryption/encryption")

var ErrCertIsNotACaCert error = errors.New("the certificate provided is not a CA certificate")
var ErrPemBlockTypeNotSupported error = errors.New("the pem block type is not supported")

var ErrCaCertIsMissing error = errors.New("the CA certificate is missing")
var ErrCaPrivateKeyIsMissing error = errors.New("the CA private key is missing")
var ErrCertDoesntMatchKey error = errors.New("the private key doesn't match the certificate public key")

var ErrExportFormatNotSupported error = errors.New("unsupported export format")

var ErrCertificateNotFound error = errors.New("certificate not found")
var ErrPrivateKeyNotFound error = errors.New("private key not found")
