package CryptoUtils

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
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
func (p *Pki) ResetCa() {
	p.caKey = nil
	p.caCert = nil
	p.ResetLeaf()
}

// ResetLeaf resets the internal certificate
func (p *Pki) ResetLeaf() {
	p.key = nil
	p.cert = nil
}

// InitCaFromPem InitCa expects a CA certificate in PEM format as a bytes slice
// It returns an error when:
//   - the cert and/or the key are not present.
//   - a pem block with an unsupported type is encountered
//   - the certificate and the private key don't match
func (p *Pki) InitCaFromPem(pemBytes []byte) error {
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
				p.caCert = caCert
			} else {
				p.caKey = nil
				return ErrCertIsNotACaCert
			}
		case pemHeaderPrivateRSA:
			p.caKey = new(PrivateKey)
			if err = p.caKey.parseDerBytesAsRsa(pemBlock.Bytes); err != nil {
				return err
			}
		case pemHeaderPrivateECDSA:
			p.caKey = new(PrivateKey)
			if err = p.caKey.parseDerBytesAsEcdsa(pemBlock.Bytes); err != nil {
				return err
			}
		case pemHeaderPrivateED25519:
			p.caKey = new(PrivateKey)
			if err = p.caKey.parseDerBytesAsEd25519(pemBlock.Bytes); err != nil {
				return err
			}
		default:
			return ErrPemBlockTypeNotSupported
		}
	}
	switch {
	case p.caCert == nil:
		return ErrCaCertIsMissing
	case p.caKey == nil:
		return ErrCaPrivateKeyIsMissing
	case !p.keyPairIsValid(p.caKey.getPrivate(), p.caCert.PublicKey):
		p.caCert = nil
		p.caKey = nil
		return ErrCertDoesntMatchKey
	}
	return nil
}

// GenerateCertRsaKeys generates an RSA private key for the certificate with a length of keySize (int)
func (p *Pki) GenerateCertRsaKeys(keySize int) error {
	return p.generateKeys(Rsa, keySize, nil, false)
}

// GenerateCaRsaKeys generates an RSA private key for the CA certificate with a length of keySize (int)
func (p *Pki) GenerateCaRsaKeys(keySize int) error {
	return p.generateKeys(Rsa, keySize, nil, true)
}

// GenerateCertEcdsaKeys generates an ECDSA private key for the certificate based on the curve provided as argument
func (p *Pki) GenerateCertEcdsaKeys(curve elliptic.Curve) error {
	return p.generateKeys(Ecdsa, 0, curve, false)
}

// GenerateCaEcdsaKeys generates an ECDSA private key for the CA certificate based on the curve provided as argument
func (p *Pki) GenerateCaEcdsaKeys(curve elliptic.Curve) error {
	return p.generateKeys(Ecdsa, 0, curve, true)
}

// GenerateCertEd25519Keys generates an ED25519 private key for the certificate
func (p *Pki) GenerateCertEd25519Keys() error {
	return p.generateKeys(Ed25519, 0, nil, false)
}

// GenerateCaEd25519Keys generates an ED25519 private key for the CA certificate
func (p *Pki) GenerateCaEd25519Keys() error {
	return p.generateKeys(Ed25519, 0, nil, true)
}

// generateKeys generates a private key
func (p *Pki) generateKeys(keyType KeyType, keySize int, curve elliptic.Curve, ca bool) error {
	var target *PrivateKey
	if ca {
		p.caKey = new(PrivateKey)
		target = p.caKey
		p.caCert = nil
	} else {
		p.key = new(PrivateKey)
		target = p.key
		p.cert = nil
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
		return ErrUnknownKeyType
	}
}

// GenerateCaCert generates the CA certificate based on the certificate description provided
func (p *Pki) GenerateCaCert(desc *CertificateDescription) error {
	var err error

	if desc == nil {
		return fmt.Errorf("no certificate description provided")
	}

	if p.caKey == nil {
		err = p.GenerateCaRsaKeys(defaultRsaKeySize)
		if err != nil {
			return fmt.Errorf("the ca key was not set, error encountered while generating it with the default values: %v", err)
		}
	}

	desc.keyUsage = desc.keyUsage | x509.KeyUsageCertSign

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
	p.caCert = desc.getCertificate()

	return nil
}

// GenerateCert generates the certificate based on the certificate description provided
func (p *Pki) GenerateCert(desc *CertificateDescription) error {
	var err error

	if desc == nil {
		return fmt.Errorf("no certificate description provided")
	}

	if p.key == nil {
		err = p.GenerateCertRsaKeys(defaultRsaKeySize)
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
	p.cert = desc.getCertificate()

	return nil
}

// ExportCa exports the CA certificate with the related private key in the expected format (only the PEM format is supported so far)
func (p *Pki) ExportCa(format ExportFormat) ([]byte, error) {
	return p.export(format, true)
}

// GetCaCert return the CA certificate
func (p *Pki) GetCaCert() *x509.Certificate {
	return p.caCert
}

// ExportCert exports the certificate with the related private key in the expected format (only the PEM format is supported so far)
func (p *Pki) ExportCert(format ExportFormat) ([]byte, error) {
	return p.export(format, false)
}

// export exports a certificate and returns an error when the desired format is not supported
func (p *Pki) export(format ExportFormat, ca bool) ([]byte, error) {
	switch format {
	case FormatPEM:
		return p.exportAsPem(ca)
	default:
		return nil, ErrExportFormatNotSupported
	}
}

// exportAsPem exports a certificate in PEM format
func (p *Pki) exportAsPem(ca bool) ([]byte, error) {
	var err error
	var keyPub crypto.PublicKey
	var caCert *x509.Certificate
	var cert *x509.Certificate
	var pemBytes []byte
	var pemBlock = new(pem.Block)

	if ca {
		switch p.caKey.GetType() {
		case Rsa:
			if keyPub, err = p.caKey.GetPublicRsa(); err != nil {
				return nil, err
			}
		case Ecdsa:
			if keyPub, err = p.caKey.GetPublicEcdsa(); err != nil {
				return nil, err
			}
		case Ed25519:
			if keyPub, err = p.caKey.GetPublicEd25519(); err != nil {
				return nil, err
			}
		case keyNotSet:
			return nil, ErrCaPrivateKeyIsMissing
		}
		if pemBytes, err = p.caKey.EncodePrivateKeyAsPem(); err != nil {
			return nil, err
		}
		caCert = p.caCert
		cert = p.caCert
	} else {
		switch p.key.GetType() {
		case Rsa:
			if keyPub, err = p.key.GetPublicRsa(); err != nil {
				return nil, err
			}
		case Ecdsa:
			if keyPub, err = p.key.GetPublicEcdsa(); err != nil {
				return nil, err
			}
		case Ed25519:
			if keyPub, err = p.key.GetPublicEd25519(); err != nil {
				return nil, err
			}
		case keyNotSet:
			return nil, ErrPrivateKeyNotSet
		}
		if pemBytes, err = p.key.EncodePrivateKeyAsPem(); err != nil {
			return nil, err
		}
		caCert = p.caCert
		cert = p.cert
	}

	if pemBlock.Bytes, err = x509.CreateCertificate(rand.Reader, cert, caCert, keyPub, p.caKey); err != nil {
		return nil, err
	}
	pemBlock.Type = "CERTIFICATE"
	pemBytes = append(pemBytes, pem.EncodeToMemory(pemBlock)...)
	return pemBytes, nil
}

func (p *Pki) keyPairIsValid(priv crypto.PrivateKey, pub crypto.PublicKey) bool {
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

// ConvertPemDataToTlsCertificateStructure
func ConvertPemDataToTlsCertificateStructure(pemBytes []byte) (*tls.Certificate, error) {
	var err error
	var pemBlock *pem.Block
	var rest []byte
	var tlsCertificate *tls.Certificate = new(tls.Certificate)
	var crtDone, keyDone bool
	tlsCertificate.Certificate = make([][]byte, 0)

	for pemBlock, rest = pem.Decode(pemBytes); pemBlock != nil; pemBlock, rest = pem.Decode(rest) {
		switch pemBlock.Type {
		case "CERTIFICATE":
			tlsCertificate.Certificate = append(tlsCertificate.Certificate, pemBlock.Bytes)
			crtDone = true
		case pemHeaderPrivateRSA:
			if tlsCertificate.PrivateKey, err = x509.ParsePKCS1PrivateKey(pemBlock.Bytes); err != nil {
				return nil, err
			}
			keyDone = true
		case pemHeaderPrivateECDSA:
			if tlsCertificate.PrivateKey, err = x509.ParseECPrivateKey(pemBlock.Bytes); err != nil {
				return nil, err
			}
			keyDone = true
		case pemHeaderPrivateED25519:
			if tlsCertificate.PrivateKey, err = x509.ParsePKCS8PrivateKey(pemBlock.Bytes); err != nil {
				return nil, err
			}
			keyDone = true
		default:
			return nil, fmt.Errorf("the pem block type \"%s\" is not supported", pemBlock.Type)
		}
	}
	if !crtDone {
		return nil, ErrCertificateNotFound
	}
	if !keyDone {
		return nil, ErrPrivateKeyNotFound
	}
	return tlsCertificate, nil
}
