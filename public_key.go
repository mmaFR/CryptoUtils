package CryptoUtils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

const (
	pemHeaderPublicRSA     string = "RSA PUBLIC KEY"
	pemHeaderPublicECDSA   string = "EC PUBLIC KEY"
	pemHeaderPublicED25519 string = "PUBLIC KEY"
)

type PublicKey struct {
	rsaKey     *rsa.PublicKey
	ecdsaKey   *ecdsa.PublicKey
	ed25519Key ed25519.PublicKey
}

// Public returns the public key as crypto.PublicKey for the key type in use.
//
// It is a crypto.Signer implementation.
func (pk *PublicKey) Public() crypto.PublicKey {
	switch pk.GetType() {
	case Rsa:
		return pk.rsaKey
	case Ecdsa:
		return pk.ecdsaKey
	case Ed25519:
		return pk.ed25519Key
	default:
		return nil
	}
}

// Reset replace all the embedded keys by nil
func (pk *PublicKey) Reset() {
	pk.rsaKey = nil
}

// GetType returns the key type in use
func (pk *PublicKey) GetType() KeyType {
	switch {
	case pk.rsaKey != nil:
		return Rsa
	case pk.ecdsaKey != nil:
		return Ecdsa
	case pk.ed25519Key != nil:
		return Ed25519
	default:
		return keyNotSet
	}
}

// GetPublicRsa returns the embedded RSA public key as *rsa.PublicKey and an error if it is not the key type in use
func (pk *PublicKey) GetPublicRsa() (*rsa.PublicKey, error) {
	if pk.rsaKey == nil {
		return nil, ErrRsaKeyPairNotInitialized
	}
	var keyCopy rsa.PublicKey = *pk.rsaKey
	return &keyCopy, nil
}

// EncodePublicKeyAsPem returns the public key in use as a slice of bytes in PEM format
func (pk *PublicKey) EncodePublicKeyAsPem() (pemBytes []byte, err error) { // the returned error is here to be consistent with the PrivateKey API
	var pemBlock *pem.Block = new(pem.Block)
	pemBlock.Type = "RSA PUBLIC KEY"
	pemBlock.Bytes = x509.MarshalPKCS1PublicKey(pk.rsaKey)
	pemBytes = pem.EncodeToMemory(pemBlock)
	return
}

// ParsePemBytes expects a slice of bytes representing a PEM file content. It will consume the bytes slice until a private key is found.
//
// An error is returned if no supported (only RSA, ECDSA, and ED25519 are supported so far) private is found, or if an error is encountered during the key decoding.
func (pk *PublicKey) ParsePemBytes(b []byte) error {
	var pemBlock *pem.Block
	var rest []byte
	for pemBlock, rest = pem.Decode(b); pemBlock != nil; pemBlock, rest = pem.Decode(rest) {
		switch pemBlock.Type {
		case pemHeaderPublicRSA: //RSA
			return pk.parseDerBytesAsRsa(pemBlock.Bytes)
		case pemHeaderPublicECDSA: //ECDSA
			return pk.parseDerBytesAsEcdsa(pemBlock.Bytes)
		case pemHeaderPublicED25519: //ED25519
			return pk.parseDerBytesAsEd25519(pemBlock.Bytes)
		}
	}
	return ErrUnknownKeyType
}

// ParseDerBytes expects a slice of bytes representing the private key in DER format, and the type of key to decode (Rsa, Ecdsa, or Ed25519).
//
// An error is returned if any is encountered during the decoding.
func (pk *PublicKey) ParseDerBytes(der []byte, keyType KeyType) error {
	switch keyType {
	case Rsa:
		return pk.parseDerBytesAsRsa(der)
	case Ecdsa:
		return pk.parseDerBytesAsEcdsa(der)
	case Ed25519:
		return pk.parseDerBytesAsEd25519(der)
	default:
		return ErrUnknownKeyType
	}
}

func (pk *PublicKey) parseDerBytesAsRsa(der []byte) error {
	var err error
	pk.rsaKey, err = x509.ParsePKCS1PublicKey(der)
	return err
}
func (pk *PublicKey) parseDerBytesAsEcdsa(der []byte) error {
	var err error
	var genericKey any
	genericKey, err = x509.ParsePKIXPublicKey(der)
	pk.ecdsaKey = genericKey.(*ecdsa.PublicKey)
	return err
}
func (pk *PublicKey) parseDerBytesAsEd25519(der []byte) error {
	var err error
	var genericKey any
	if genericKey, err = x509.ParsePKIXPublicKey(der); err != nil {
		return err
	}
	pk.ed25519Key = genericKey.(ed25519.PublicKey)
	return nil
}

func (pk *PublicKey) EncryptMessage(msg []byte) ([]byte, error) {
	switch pk.GetType() {
	case Rsa:
		return pk.encryptMessageWithRsa(msg)
	case Ecdsa:
		return pk.encryptMessageWithEcdsa(msg)
	case Ed25519:
		return pk.encryptMessageWithEd25519(msg)
	case keyNotSet:
		return nil, ErrPrivateKeyNotSet
	default:
		return nil, ErrUnknownKeyType
	}
}

func (pk *PublicKey) encryptMessageWithRsa(msg []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, pk.rsaKey, msg)
}
func (pk *PublicKey) encryptMessageWithEcdsa(msg []byte) ([]byte, error) {
	return nil, ErrEcdsaNotSupported
}
func (pk *PublicKey) encryptMessageWithEd25519(msg []byte) ([]byte, error) {
	return nil, ErrEd25519NotSupported
}
