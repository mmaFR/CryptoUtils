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

const (
	keyNotSet KeyType = iota
	Rsa
	Ecdsa
	Ed25519
)

const (
	errKeyNotYetInitialized string = "key pair not yet initialized"
)

type PrivateKey struct {
	rsaKey         *rsa.PrivateKey
	ecdsaKey       *ecdsa.PrivateKey
	ed25519PrivKey ed25519.PrivateKey
}

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

func (pk *PrivateKey) Reset() {
	pk.rsaKey = nil
	pk.ecdsaKey = nil
	pk.ed25519PrivKey = nil
}
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

func (pk *PrivateKey) GenerateRsa(size int) (err error) {
	pk.rsaKey, err = rsa.GenerateKey(rand.Reader, size)
	pk.ed25519PrivKey = nil
	pk.ecdsaKey = nil
	return
}
func (pk *PrivateKey) GetPrivateRsa() (*rsa.PrivateKey, error) {
	if pk.rsaKey == nil {
		return nil, errors.New(errKeyNotYetInitialized)
	}
	var keyCopy rsa.PrivateKey = *pk.rsaKey
	return &keyCopy, nil
}
func (pk *PrivateKey) GetPublicRsa() (*rsa.PublicKey, error) {
	if pk.rsaKey == nil {
		return nil, errors.New("rsa key pair not yet initialized")
	}
	var keyCopy rsa.PublicKey = pk.rsaKey.PublicKey
	return &keyCopy, nil
}

func (pk *PrivateKey) GenerateEcdsa(curve elliptic.Curve) (err error) {
	pk.rsaKey = nil
	pk.ed25519PrivKey = nil
	pk.ecdsaKey, err = ecdsa.GenerateKey(curve, rand.Reader)
	return
}
func (pk *PrivateKey) GetPrivateEcdsa() (*ecdsa.PrivateKey, error) {
	if pk.ecdsaKey == nil {
		return nil, errors.New(errKeyNotYetInitialized)
	}
	var keyCopy ecdsa.PrivateKey = *pk.ecdsaKey
	return &keyCopy, nil
}
func (pk *PrivateKey) GetPublicEcdsa() (*ecdsa.PublicKey, error) {
	if pk.ecdsaKey == nil {
		return nil, errors.New("rsa key pair not yet initialized")
	}
	var keyCopy ecdsa.PublicKey = pk.ecdsaKey.PublicKey
	return &keyCopy, nil
}

func (pk *PrivateKey) GenerateEd25519() (err error) {
	pk.rsaKey = nil
	pk.ecdsaKey = nil
	_, pk.ed25519PrivKey, err = ed25519.GenerateKey(rand.Reader)
	return
}
func (pk *PrivateKey) GetPrivateEd25519() (ed25519.PrivateKey, error) {
	if pk.ed25519PrivKey == nil {
		return nil, errors.New(errKeyNotYetInitialized)
	}
	var keyCopy ed25519.PrivateKey
	copy(keyCopy, pk.ed25519PrivKey)
	keyCopy.Public()
	return keyCopy, nil
}
func (pk *PrivateKey) GetPublicEd25519() (ed25519.PublicKey, error) {
	var keyPub []byte = make([]byte, ed25519.PublicKeySize)
	copy(keyPub, pk.ed25519PrivKey[32:])
	return keyPub, nil
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

func (pk *PrivateKey) EncodePrivateKeyAsPem() ([]byte, error) {
	return pk.encodeKeyAsPem(true)
}
func (pk *PrivateKey) EncodePublicKeyAsPem() ([]byte, error) {
	return pk.encodeKeyAsPem(false)
}
func (pk *PrivateKey) encodeKeyAsPem(private bool) (pemBytes []byte, err error) {
	var keyType KeyType = pk.GetType()
	var pemBlock *pem.Block = new(pem.Block)

	if private {
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

func (pk *PrivateKey) ParseBytes(b []byte, keyType KeyType) error {
	switch keyType {
	case Rsa:
		return pk.parseRsa(b)
	case Ecdsa:
		return pk.parseEcdsa(b)
	case Ed25519:
		return pk.parseEd25519(b)
	default:
		return errors.New("unable to parse unknown key type")
	}
}
func (pk *PrivateKey) parseRsa(b []byte) error {
	var err error
	pk.rsaKey, err = x509.ParsePKCS1PrivateKey(b)
	return err
}
func (pk *PrivateKey) parseEcdsa(b []byte) error {
	var err error
	pk.ecdsaKey, err = x509.ParseECPrivateKey(b)
	return err
}
func (pk *PrivateKey) parseEd25519(b []byte) error {
	var err error
	var key any
	if key, err = x509.ParsePKCS8PrivateKey(b); err != nil {
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
