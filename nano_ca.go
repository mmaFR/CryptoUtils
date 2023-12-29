package CryptoUtils

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

type ExportFormat uint8

const (
	FormatPEM ExportFormat = 1 + iota
)

const defaultRsaKeySize int = 2048

type Pki struct {
	caKey  *PrivateKey
	caCert *x509.Certificate
	key    *PrivateKey
	cert   *x509.Certificate
}

// ResetCa resets the internal CA and certificate
func (g *Pki) ResetCa() {
	g.caKey = nil
	g.caCert = nil
	g.ResetLeaf()
}

// ResetLeaf resets the internal certificate
func (g *Pki) ResetLeaf() {
	g.key = nil
	g.cert = nil
}

// InitCaFromPem InitCa expects a CA certificate in PEM format as a bytes slice
// It returns an error when:
//   - the cert and/or the key are not present.
//   - a pem block with an unsupported type is encountered
//   - the certificate and the private key don't match
func (g *Pki) InitCaFromPem(pemBytes []byte) error {
	var err error
	var pemBlock *pem.Block
	var rest []byte

	for pemBlock, rest = pem.Decode(pemBytes); pemBlock != nil; pemBlock, rest = pem.Decode(rest) {
		switch pemBlock.Type {
		case "CERTIFICATE":
			var caCert *x509.Certificate
			if caCert, err = x509.ParseCertificate(pemBlock.Bytes); err != nil {
				return err
			}
			if caCert.IsCA {
				g.caCert = caCert
			} else {
				g.caKey = nil
				return errors.New("the certificate provided is not a CA certificate")
			}
		case pemHeaderRSA, pemHeaderECDSA, pemHeaderED25519:
			g.caKey = new(PrivateKey)
			if err = g.caKey.ParsePemBytes(pemBlock.Bytes); err != nil {
				return err
			}
		default:
			return fmt.Errorf("the pem block type \"%s\" is not supported", pemBlock.Type)
		}
	}
	switch {
	case g.caCert == nil:
		return errors.New("the CA certificate is missing")
	case g.caKey == nil:
		return errors.New("the CA private key is missing")
	case !g.keyPairIsValid(g.caKey.getPrivate(), g.caCert.PublicKey):
		g.caCert = nil
		g.caKey = nil
		return errors.New("the private key doesn't match the certificate public key")
	}
	return nil
}

// GenerateCertRsaKeys generates an RSA private key for the certificate with a length of keySize (int)
func (g *Pki) GenerateCertRsaKeys(keySize int) error {
	return g.generateKeys(Rsa, keySize, nil, false)
}

// GenerateCaRsaKeys generates an RSA private key for the CA certificate with a length of keySize (int)
func (g *Pki) GenerateCaRsaKeys(keySize int) error {
	return g.generateKeys(Rsa, keySize, nil, true)
}

// GenerateCertEcdsaKeys generates an ECDSA private key for the certificate based on the curve provided as argument
func (g *Pki) GenerateCertEcdsaKeys(curve elliptic.Curve) error {
	return g.generateKeys(Ecdsa, 0, curve, false)
}

// GenerateCaEcdsaKeys generates an ECDSA private key for the CA certificate based on the curve provided as argument
func (g *Pki) GenerateCaEcdsaKeys(curve elliptic.Curve) error {
	return g.generateKeys(Ecdsa, 0, curve, true)
}

// GenerateCertEd25519Keys generates an ED25519 private key for the certificate
func (g *Pki) GenerateCertEd25519Keys() error {
	return g.generateKeys(Ed25519, 0, nil, false)
}

// GenerateCaEd25519Keys generates an ED25519 private key for the CA certificate
func (g *Pki) GenerateCaEd25519Keys() error {
	return g.generateKeys(Ed25519, 0, nil, true)
}

// generateKeys generates a private key
func (g *Pki) generateKeys(keyType KeyType, keySize int, curve elliptic.Curve, ca bool) error {
	var target *PrivateKey
	if ca {
		g.caKey = new(PrivateKey)
		target = g.caKey
		g.caCert = nil
	} else {
		g.key = new(PrivateKey)
		target = g.key
		g.cert = nil
	}

	switch keyType {
	case Rsa:
		if keySize == 1024 || keySize == 2048 || keySize == 4096 || keySize == 8192 {
			return target.GenerateRsa(keySize)
		} else {
			return errors.New("1024, 2048, 4096, and 8192 are the only key sizes supported for RSA so far")
		}
	case Ecdsa:
		return target.GenerateEcdsa(curve)
	case Ed25519:
		return target.GenerateEd25519()
	default:
		return errors.New("unexpected error during keys generation")
	}
}

// GenerateCaCert generates the CA certificate based on the certificate description provided
func (g *Pki) GenerateCaCert(desc *CertificateDescription) error {
	var err error

	if desc == nil {
		return fmt.Errorf("no certificate description provided")
	}

	if g.caKey == nil {
		err = g.GenerateCaRsaKeys(defaultRsaKeySize)
		if err != nil {
			return fmt.Errorf("the ca key was not set, error encountered while generating it with the default values: %v", err)
		}
	}

	//g.caCert = &x509.Certificate{
	//	SerialNumber: desc.serialNumber,
	//	Subject: pkix.Name{
	//		Country:            desc.GetCountry(),
	//		Organization:       desc.GetOrganization(),
	//		OrganizationalUnit: desc.GetOrganizationalUnit(),
	//		Locality:           desc.GetLocality(),
	//		Province:           desc.GetProvince(),
	//		StreetAddress:      desc.GetStreetAddress(),
	//		PostalCode:         desc.GetPostalCode(),
	//		//CommonName:         "",
	//		//Names:              nil,
	//		//ExtraNames:         nil,
	//	},
	//	NotBefore:             desc.notValidBefore,
	//	NotAfter:              desc.notValidAfter,
	//	KeyUsage:              desc.keyUsage,
	//	ExtKeyUsage:           desc.extKeyUsage,
	//	BasicConstraintsValid: desc.basicConstraintsValid,
	//	IsCA:                  desc.isCa,
	//	//MaxPathLen:                  0,
	//	//MaxPathLenZero:              false,
	//	//SubjectKeyId:                nil,
	//	//AuthorityKeyId:              nil,
	//	//OCSPServer:                  nil,
	//	//IssuingCertificateURL:       nil,
	//	//DNSNames:                    nil,
	//	//EmailAddresses:              nil,
	//	//IPAddresses:                 nil,
	//	//URIs:                        nil,
	//	//PermittedDNSDomainsCritical: false,
	//	//PermittedDNSDomains:         nil,
	//	//ExcludedDNSDomains:          nil,
	//	//PermittedIPRanges:           nil,
	//	//ExcludedIPRanges:            nil,
	//	//PermittedEmailAddresses:     nil,
	//	//ExcludedEmailAddresses:      nil,
	//	//PermittedURIDomains:         nil,
	//	//ExcludedURIDomains:          nil,
	//	//CRLDistributionPoints:       nil,
	//	//PolicyIdentifiers:           nil,
	//}
	g.caCert = desc.getCertificate()

	return nil
}

// GenerateCert generates the certificate based on the certificate description provided
func (g *Pki) GenerateCert(desc *CertificateDescription) error {
	var err error

	if desc == nil {
		return fmt.Errorf("no certificate description provided")
	}

	if g.key == nil {
		err = g.GenerateCertRsaKeys(defaultRsaKeySize)
		if err != nil {
			return fmt.Errorf("the certificate key was not set, error encountered while generating it with the default values: %v", err)
		}
	}

	//g.cert = &x509.Certificate{
	//	SerialNumber: desc.serialNumber,
	//	Issuer:       g.caCert.Issuer,
	//	Subject: pkix.Name{
	//		Country:            []string{desc.country},
	//		Organization:       []string{desc.organization},
	//		OrganizationalUnit: []string{desc.organizationalUnit},
	//		Locality:           []string{desc.locality},
	//		Province:           []string{desc.province},
	//		StreetAddress:      []string{desc.streetAddress},
	//		PostalCode:         []string{desc.postalCode},
	//		SerialNumber:       "",
	//		CommonName:         "",
	//		Names:              nil,
	//		ExtraNames:         nil,
	//	},
	//	NotBefore:                   time.Time{},
	//	NotAfter:                    time.Time{},
	//	KeyUsage:                    0,
	//	Extensions:                  nil,
	//	ExtraExtensions:             nil,
	//	UnhandledCriticalExtensions: nil,
	//	ExtKeyUsage:                 nil,
	//	UnknownExtKeyUsage:          nil,
	//	BasicConstraintsValid:       false,
	//	IsCA:                        false,
	//	MaxPathLen:                  0,
	//	MaxPathLenZero:              false,
	//	SubjectKeyId:                nil,
	//	AuthorityKeyId:              nil,
	//	OCSPServer:                  nil,
	//	IssuingCertificateURL:       nil,
	//	DNSNames:                    nil,
	//	EmailAddresses:              nil,
	//	IPAddresses:                 nil,
	//	URIs:                        nil,
	//	PermittedDNSDomainsCritical: false,
	//	PermittedDNSDomains:         nil,
	//	ExcludedDNSDomains:          nil,
	//	PermittedIPRanges:           nil,
	//	ExcludedIPRanges:            nil,
	//	PermittedEmailAddresses:     nil,
	//	ExcludedEmailAddresses:      nil,
	//	PermittedURIDomains:         nil,
	//	ExcludedURIDomains:          nil,
	//	CRLDistributionPoints:       nil,
	//	PolicyIdentifiers:           nil,
	//}
	g.cert = desc.getCertificate()

	return nil
}

// ExportCa exports the CA certificate with the related private key in the expected format (only the PEM format is supported so far)
func (g *Pki) ExportCa(format ExportFormat) ([]byte, error) {
	return g.export(format, true)
}

// ExportCert exports the certificate with the related private key in the expected format (only the PEM format is supported so far)
func (g *Pki) ExportCert(format ExportFormat) ([]byte, error) {
	return g.export(format, false)
}

// export exports a certificate and returns an error when the desired format is not supported
func (g *Pki) export(format ExportFormat, ca bool) ([]byte, error) {
	switch format {
	case FormatPEM:
		return g.exportAsPem(ca)
	default:
		return nil, errors.New("unsupported export format")
	}
}

// exportAsPem exports a certificate in PEM format
func (g *Pki) exportAsPem(ca bool) ([]byte, error) {
	var err error
	var keyPub crypto.PublicKey
	var caCert *x509.Certificate
	var cert *x509.Certificate
	var pemBytes []byte
	var pemBlock = new(pem.Block)

	if ca {
		switch g.caKey.GetType() {
		case Rsa:
			if keyPub, err = g.caKey.GetPublicRsa(); err != nil {
				return nil, err
			}
		case Ecdsa:
			if keyPub, err = g.caKey.GetPublicEcdsa(); err != nil {
				return nil, err
			}
		case Ed25519:
			if keyPub, err = g.caKey.GetPublicEd25519(); err != nil {
				return nil, err
			}
		case keyNotSet:
			return nil, errors.New("ca key not set")
		}
		if pemBytes, err = g.caKey.EncodePrivateKeyAsPem(); err != nil {
			return nil, err
		}
		caCert = g.caCert
		cert = g.caCert
	} else {
		switch g.key.GetType() {
		case Rsa:
			if keyPub, err = g.key.GetPublicRsa(); err != nil {
				return nil, err
			}
		case Ecdsa:
			if keyPub, err = g.key.GetPublicEcdsa(); err != nil {
				return nil, err
			}
		case Ed25519:
			if keyPub, err = g.key.GetPublicEd25519(); err != nil {
				return nil, err
			}
		case keyNotSet:
			return nil, errors.New("ca key not set")
		}
		if pemBytes, err = g.key.EncodePrivateKeyAsPem(); err != nil {
			return nil, err
		}
		caCert = g.caCert
		cert = g.cert
	}

	if pemBlock.Bytes, err = x509.CreateCertificate(rand.Reader, cert, caCert, keyPub, g.caKey); err != nil {
		return nil, err
	}
	pemBlock.Type = "CERTIFICATE"
	pemBytes = append(pemBytes, pem.EncodeToMemory(pemBlock)...)
	return pemBytes, nil
}

func (g *Pki) keyPairIsValid(priv crypto.PrivateKey, pub crypto.PublicKey) bool {
	type PrivateKey interface {
		Public() crypto.PublicKey
	}
	type PublicKey interface {
		Equal(key crypto.PublicKey) bool
	}

	var ok bool
	var privkey PrivateKey
	var pubkey PublicKey

	if privkey, ok = priv.(PrivateKey); !ok {
		return false
	}

	if pubkey, ok = privkey.Public().(PublicKey); !ok {
		return false
	}

	return pubkey.Equal(pub)
}

// NewPki returns a Pki pointer
func NewPki() *Pki {
	return new(Pki)
}
