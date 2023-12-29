package CryptoUtils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
)

type KeyType uint8
type KeyKind bool

const (
	keyNotSet KeyType = iota
	Rsa
	Ecdsa
	Ed25519
)

const (
	errKeyNotYetInitialized string = "key pair not yet initialized"
	pemHeaderRSA            string = "RSA PRIVATE KEY"
	pemHeaderECDSA                 = "EC PRIVATE KEY"
	pemHeaderED25519               = "PRIVATE KEY"
)

const (
	Private KeyKind = true
	Public  KeyKind = false
)

// PrivateKey key type (rsa, ecdsa, or ed25519) abstraction
type PrivateKey struct {
	rsaKey         *rsa.PrivateKey
	ecdsaKey       *ecdsa.PrivateKey
	ed25519PrivKey ed25519.PrivateKey
}

// Public returns the public key as crypto.PublicKey for the key type in use.
//
// It is a crypto.Signer implementation.
func (pk *PrivateKey) Public() crypto.PublicKey {
	switch pk.GetType() {
	case Rsa:
		return pk.rsaKey.Public()
	case Ecdsa:
		return pk.ecdsaKey.Public()
	case Ed25519:
		return pk.ed25519PrivKey.Public()
	default:
		return nil
	}
}

// Sign
//
// It is a crypto.Signer implementation.
func (pk *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	switch pk.GetType() {
	case Rsa:
		return pk.rsaKey.Sign(rand, digest, opts)
	case Ecdsa:
		return pk.ecdsaKey.Sign(rand, digest, opts)
	case Ed25519:
		return pk.ed25519PrivKey.Sign(rand, digest, opts)
	case keyNotSet:
		return nil, errors.New("key not yet set")
	default:
		return nil, errors.New("unexpected error")
	}
}

// Reset replace all the embedded keys by nil
func (pk *PrivateKey) Reset() {
	pk.rsaKey = nil
	pk.ecdsaKey = nil
	pk.ed25519PrivKey = nil
}

// GetType returns the key type in use
func (pk *PrivateKey) GetType() KeyType {
	switch {
	case pk.rsaKey != nil:
		return Rsa
	case pk.ecdsaKey != nil:
		return Ecdsa
	case pk.ed25519PrivKey != nil:
		return Ed25519
	default:
		return keyNotSet
	}
}

////////////////////
// Key generation //
////////////////////

// GenerateRsa generates an RSA key, resets the other keys and returns any error encountered
func (pk *PrivateKey) GenerateRsa(size int) (err error) {
	pk.rsaKey, err = rsa.GenerateKey(rand.Reader, size)
	pk.ed25519PrivKey = nil
	pk.ecdsaKey = nil
	return
}

// GenerateEcdsa generates an ECDSA key, resets the other keys and returns any error encountered
func (pk *PrivateKey) GenerateEcdsa(curve elliptic.Curve) (err error) {
	pk.rsaKey = nil
	pk.ed25519PrivKey = nil
	pk.ecdsaKey, err = ecdsa.GenerateKey(curve, rand.Reader)
	return
}

// GenerateEd25519 generates an ED25519 key, resets the other keys and returns any error encountered
func (pk *PrivateKey) GenerateEd25519() (err error) {
	pk.rsaKey = nil
	pk.ecdsaKey = nil
	_, pk.ed25519PrivKey, err = ed25519.GenerateKey(rand.Reader)
	return
}

////////////////////////
// Private key getter //
////////////////////////

// GetPrivateRsa returns the embedded RSA private key as *rsa.PrivateKey and an error if it is not the key type in use
func (pk *PrivateKey) GetPrivateRsa() (*rsa.PrivateKey, error) {
	if pk.rsaKey == nil {
		return nil, errors.New(errKeyNotYetInitialized)
	}
	var keyCopy rsa.PrivateKey = *pk.rsaKey
	return &keyCopy, nil
}

// GetPrivateEcdsa returns the embedded ECDSA private key as *ecdsa.PrivateKey and an error if it is not the key type in use
func (pk *PrivateKey) GetPrivateEcdsa() (*ecdsa.PrivateKey, error) {
	if pk.ecdsaKey == nil {
		return nil, errors.New(errKeyNotYetInitialized)
	}
	var keyCopy ecdsa.PrivateKey = *pk.ecdsaKey
	return &keyCopy, nil
}

// GetPrivateEd25519 returns the embedded ED25519 private key as *ed25519.PrivateKey and an error if it is not the key type in use
func (pk *PrivateKey) GetPrivateEd25519() (ed25519.PrivateKey, error) {
	if pk.ed25519PrivKey == nil {
		return nil, errors.New(errKeyNotYetInitialized)
	}
	var keyCopy ed25519.PrivateKey
	copy(keyCopy, pk.ed25519PrivKey)
	keyCopy.Public()
	return keyCopy, nil
}

func (pk *PrivateKey) getPrivate() crypto.PrivateKey {
	switch pk.GetType() {
	case Rsa:
		return pk.rsaKey
	case Ecdsa:
		return pk.ecdsaKey
	case Ed25519:
		return pk.ed25519PrivKey
	default:
		return nil
	}
}

///////////////////////
// Public key getter //
///////////////////////

// GetPublicRsa returns the embedded RSA public key as *rsa.PublicKey and an error if it is not the key type in use
func (pk *PrivateKey) GetPublicRsa() (*rsa.PublicKey, error) {
	if pk.rsaKey == nil {
		return nil, errors.New("rsa key pair not yet initialized")
	}
	var keyCopy rsa.PublicKey = pk.rsaKey.PublicKey
	return &keyCopy, nil
}

// GetPublicEcdsa returns the embedded ECDSA public key as *ecdsa.PublicKey and an error if it is not the key type in use
func (pk *PrivateKey) GetPublicEcdsa() (*ecdsa.PublicKey, error) {
	if pk.ecdsaKey == nil {
		return nil, errors.New("rsa key pair not yet initialized")
	}
	var keyCopy ecdsa.PublicKey = pk.ecdsaKey.PublicKey
	return &keyCopy, nil
}

// GetPublicEd25519 returns the embedded ED25519 public key as *ed25519.PublicKey and an error if it is not the key type in use
func (pk *PrivateKey) GetPublicEd25519() (ed25519.PublicKey, error) {
	var keyPub []byte = make([]byte, ed25519.PublicKeySize)
	copy(keyPub, pk.ed25519PrivKey[32:])
	return keyPub, nil
}

//////////////
// Encoding //
//////////////

// EncodePrivateKeyAsPem returns the private key in use as a slice of bytes in PEM format
func (pk *PrivateKey) EncodePrivateKeyAsPem() ([]byte, error) {
	return pk.encodeKeyAsPem(Private)
}

// EncodePublicKeyAsPem returns the public key in use as a slice of bytes in PEM format
func (pk *PrivateKey) EncodePublicKeyAsPem() ([]byte, error) {
	return pk.encodeKeyAsPem(Public)
}

func (pk *PrivateKey) encodeKeyAsPem(kind KeyKind) (pemBytes []byte, err error) {
	var keyType KeyType = pk.GetType()
	var pemBlock *pem.Block = new(pem.Block)

	if kind == Private {
		switch keyType {
		case Rsa:
			pemBlock.Type = "RSA PRIVATE KEY"
			pemBlock.Bytes = x509.MarshalPKCS1PrivateKey(pk.rsaKey)
			pemBytes = pem.EncodeToMemory(pemBlock)
			return
		case Ecdsa:
			pemBlock.Type = "EC PRIVATE KEY"
			if pemBlock.Bytes, err = x509.MarshalECPrivateKey(pk.ecdsaKey); err != nil {
				return nil, err
			}
			pemBytes = pem.EncodeToMemory(pemBlock)
			return
		case Ed25519:
			//return nil, errors.New("ed25519 not yet fully supported")
			pemBlock.Type = "PRIVATE KEY"
			if pemBlock.Bytes, err = x509.MarshalPKCS8PrivateKey(pk.ed25519PrivKey); err != nil {
				return nil, err
			}
			pemBytes = pem.EncodeToMemory(pemBlock)
			return
		case keyNotSet:
			err = errors.New(errKeyNotYetInitialized)
			return
		}
	} else {
		switch keyType {
		case Rsa:
			pemBlock.Type = "RSA PUBLIC KEY"
			pemBlock.Bytes = x509.MarshalPKCS1PublicKey(&pk.rsaKey.PublicKey)
			pemBytes = pem.EncodeToMemory(pemBlock)
			return
		case Ecdsa:
			pemBlock.Type = "PUBLIC KEY"
			pemBlock.Bytes, err = x509.MarshalPKIXPublicKey(pk.ecdsaKey)
			if err != nil {
				return nil, err
			}
			pemBytes = pem.EncodeToMemory(pemBlock)
			return
		case Ed25519:
			pemBlock.Type = "PUBLIC KEY"
			if pemBlock.Bytes, err = x509.MarshalPKIXPublicKey(pk.ed25519PrivKey.Public()); err != nil {
				return nil, err
			}
			pemBytes = pem.EncodeToMemory(pemBlock)
			return
		case keyNotSet:
			err = errors.New(errKeyNotYetInitialized)
			return
		}
	}
	//This point should never be reached, this last "return" is just here to please to compiler
	return
}

//////////////
// Decoding //
//////////////

// ParsePemBytes expects a slice of bytes representing a PEM file content. It will consume the bytes slice until a private key is found.
//
// An error is returned if no supported (only RSA, ECDSA, and ED25519 are supported so far) private is found, or if an error is encountered during the key decoding.
func (pk *PrivateKey) ParsePemBytes(b []byte) error {
	var pemBlock *pem.Block
	var rest []byte
	for pemBlock, rest = pem.Decode(b); pemBlock != nil; pemBlock, rest = pem.Decode(rest) {
		switch pemBlock.Type {
		case "RSA PRIVATE KEY": //RSA
			return pk.parseDerBytesAsRsa(pemBlock.Bytes)
		case "EC PRIVATE KEY": //ECDSA
			return pk.parseDerBytesAsEcdsa(pemBlock.Bytes)
		case "PRIVATE KEY": //ED25519
			return pk.parseDerBytesAsEd25519(pemBlock.Bytes)
		}
	}
	return errors.New("unknown key type")
}

// ParseDerBytes expects a slice of bytes representing the private key in DER format, and the type of key to decode (Rsa, Ecdsa, or Ed25519).
//
// An error is returned if any is encountered during the decoding.
func (pk *PrivateKey) ParseDerBytes(der []byte, keyType KeyType) error {
	switch keyType {
	case Rsa:
		return pk.parseDerBytesAsRsa(der)
	case Ecdsa:
		return pk.parseDerBytesAsEcdsa(der)
	case Ed25519:
		return pk.parseDerBytesAsEd25519(der)
	default:
		return errors.New("unable to parse unknown key type")
	}
}

func (pk *PrivateKey) parseDerBytesAsRsa(der []byte) error {
	var err error
	pk.rsaKey, err = x509.ParsePKCS1PrivateKey(der)
	return err
}
func (pk *PrivateKey) parseDerBytesAsEcdsa(der []byte) error {
	var err error
	pk.ecdsaKey, err = x509.ParseECPrivateKey(der)
	return err
}
func (pk *PrivateKey) parseDerBytesAsEd25519(der []byte) error {
	var err error
	var key any
	if key, err = x509.ParsePKCS8PrivateKey(der); err != nil {
		return err
	}
	switch key.(type) {
	case ed25519.PrivateKey:
		pk.ed25519PrivKey = key.(ed25519.PrivateKey)
	default:
		return errors.New("the private key should be an ed25519 key but it is not")
	}
	return nil
}
