package CryptoUtils

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

// CertificateDescription represents the different certificate parameters to use to generate it.
type CertificateDescription struct {
	commonName              string
	subjectAlternativeNames []string
	serialNumber            big.Int
	organization            string
	organizationalUnit      string
	country                 string
	province                string
	locality                string
	streetAddress           string
	postalCode              string
	notValidBefore          time.Time
	notValidAfter           time.Time
	isCa                    bool
	extKeyUsage             []x509.ExtKeyUsage
	keyUsage                x509.KeyUsage
	basicConstraintsValid   bool
}

/////////////
// Getters //
/////////////

func (cd *CertificateDescription) GetCommonName() string {
	return cd.commonName
}
func (cd *CertificateDescription) GetSubjectAlternativeNames() []string {
	var san []string = make([]string, 0, len(cd.subjectAlternativeNames))
	copy(san, cd.subjectAlternativeNames)
	return san
}
func (cd *CertificateDescription) GetOrganization() []string {
	return []string{cd.organization}
}
func (cd *CertificateDescription) GetOrganizationalUnit() []string {
	return []string{cd.organizationalUnit}
}
func (cd *CertificateDescription) GetCountry() []string {
	return []string{cd.country}
}
func (cd *CertificateDescription) GetProvince() []string {
	return []string{cd.province}
}
func (cd *CertificateDescription) GetLocality() []string {
	return []string{cd.locality}
}
func (cd *CertificateDescription) GetStreetAddress() []string {
	return []string{cd.streetAddress}
}
func (cd *CertificateDescription) GetPostalCode() []string {
	return []string{cd.postalCode}
}
func (cd *CertificateDescription) GetNotValidBefore() time.Time {
	return cd.notValidBefore
}
func (cd *CertificateDescription) GetNotValidAfter() time.Time {
	return cd.notValidAfter
}
func (cd *CertificateDescription) GetIsCa() bool {
	return cd.isCa
}
func (cd *CertificateDescription) GetExtKeyUsage() []x509.ExtKeyUsage {
	return cd.extKeyUsage
}
func (cd *CertificateDescription) GetKeyUsage() x509.KeyUsage {
	return cd.keyUsage
}
func (cd *CertificateDescription) GetBasicConstraintsValid() bool {
	return cd.basicConstraintsValid
}
func (cd *CertificateDescription) GetSerialNumber() *big.Int {
	var sn big.Int = cd.serialNumber
	return &sn
}
func (cd *CertificateDescription) GetSubject() pkix.Name {
	return pkix.Name{
		Country:            cd.GetCountry(),
		Organization:       cd.GetOrganization(),
		OrganizationalUnit: cd.GetOrganizationalUnit(),
		Locality:           cd.GetLocality(),
		Province:           cd.GetProvince(),
		StreetAddress:      cd.GetStreetAddress(),
		PostalCode:         cd.GetPostalCode(),
		CommonName:         cd.GetCommonName(),
	}
}

/////////////
// Setters //
/////////////

func (cd *CertificateDescription) SetCommonName(cn string) *CertificateDescription {
	cd.commonName = cn
	return cd
}
func (cd *CertificateDescription) SetSubjectAlternativeNames(san []string) *CertificateDescription {
	copy(cd.subjectAlternativeNames, san)
	return cd
}
func (cd *CertificateDescription) SetOrganization(organization string) *CertificateDescription {
	cd.organization = organization
	return cd
}
func (cd *CertificateDescription) SetOrganizationalUnit(organizationalUnit string) *CertificateDescription {
	cd.organizationalUnit = organizationalUnit
	return cd
}
func (cd *CertificateDescription) SetCountry(country string) *CertificateDescription {
	cd.country = country
	return cd
}
func (cd *CertificateDescription) SetProvince(province string) *CertificateDescription {
	cd.province = province
	return cd
}
func (cd *CertificateDescription) SetLocality(locality string) *CertificateDescription {
	cd.locality = locality
	return cd
}
func (cd *CertificateDescription) SetStreetAddress(streetAddress string) *CertificateDescription {
	cd.streetAddress = streetAddress
	return cd
}
func (cd *CertificateDescription) SetPostalCode(postalCode string) *CertificateDescription {
	cd.postalCode = postalCode
	return cd
}
func (cd *CertificateDescription) SetNotValidBefore(notValidBefore time.Time) *CertificateDescription {
	cd.notValidBefore = notValidBefore
	return cd
}
func (cd *CertificateDescription) SetNotValidAfter(notValidAfter time.Time) *CertificateDescription {
	cd.notValidAfter = notValidAfter
	return cd
}
func (cd *CertificateDescription) SetIsCA() *CertificateDescription {
	cd.isCa = true
	return cd
}
func (cd *CertificateDescription) SetExtKeyUsage(extKeyUsage []x509.ExtKeyUsage) *CertificateDescription {
	copy(cd.extKeyUsage, extKeyUsage)
	return cd
}
func (cd *CertificateDescription) SetKeyUsage(ku x509.KeyUsage) *CertificateDescription {
	cd.keyUsage = ku
	return cd
}
func (cd *CertificateDescription) SetBasicConstraintsValid(basicConstraintsValid bool) *CertificateDescription {
	cd.basicConstraintsValid = basicConstraintsValid
	return cd
}
func (cd *CertificateDescription) SetSerialNumber(sn *big.Int) *CertificateDescription {
	cd.serialNumber = *sn
	return cd
}

func (cd *CertificateDescription) AddSubjectAlternativeName(san string) *CertificateDescription {
	cd.subjectAlternativeNames = append(cd.subjectAlternativeNames, san)
	return cd
}
func (cd *CertificateDescription) AddExtKeyUsage(eku x509.ExtKeyUsage) *CertificateDescription {
	cd.extKeyUsage = append(cd.extKeyUsage, eku)
	return cd
}
func (cd *CertificateDescription) AddKeyUsage(ku x509.KeyUsage) *CertificateDescription {
	cd.keyUsage = cd.keyUsage | ku
	return cd
}

func (cd *CertificateDescription) ClearSubjectAlternativeNames() *CertificateDescription {
	cd.subjectAlternativeNames = make([]string, 0)
	return cd
}
func (cd *CertificateDescription) ClearExtKeyUsage() *CertificateDescription {
	cd.extKeyUsage = make([]x509.ExtKeyUsage, 0)
	return cd
}
func (cd *CertificateDescription) ClearKeyUsage() *CertificateDescription {
	cd.keyUsage = 0
	return cd
}

func (cd *CertificateDescription) getCertificate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          cd.GetSerialNumber(),
		Subject:               cd.GetSubject(),
		NotBefore:             cd.GetNotValidBefore(),
		NotAfter:              cd.GetNotValidAfter(),
		IsCA:                  cd.GetIsCa(),
		ExtKeyUsage:           cd.GetExtKeyUsage(),
		KeyUsage:              cd.GetKeyUsage(),
		BasicConstraintsValid: cd.GetBasicConstraintsValid(),
		DNSNames:              cd.GetSubjectAlternativeNames(),
	}
}

func NewCertificateDescription() *CertificateDescription {
	return &CertificateDescription{
		commonName:              "MyDefaultCommonName",
		subjectAlternativeNames: []string{},
		serialNumber:            *big.NewInt(time.Now().Unix()),
		organization:            "HAProxy Support",
		country:                 "FR",
		province:                "IDF",
		locality:                "Paris",
		streetAddress:           "",
		postalCode:              "75000",
		notValidBefore:          time.Now(),
		notValidAfter:           time.Now().AddDate(10, 0, 0),
		isCa:                    false,
		extKeyUsage:             []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		keyUsage:                x509.KeyUsageDigitalSignature,
		basicConstraintsValid:   true,
	}
}
