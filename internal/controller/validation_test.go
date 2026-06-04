package controller

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/cert-manager/issuer-lib/controllers/signer"
	"github.com/stretchr/testify/require"

	casv1alpha1 "github.com/oci-cert-manager/oci-cas-issuer/api/v1alpha1"
)

func TestValidateIssuerSpec(t *testing.T) {
	valid := issuerObject().Spec
	require.NoError(t, validateIssuerSpec(valid))

	tests := []struct {
		name string
		mut  func(*casv1alpha1.IssuerSpec)
		want string
	}{
		{"bad ca ocid", func(s *casv1alpha1.IssuerSpec) { s.CertificateAuthorityID = "ocid1.certificate.oc1.test" }, "certificateAuthorityId"},
		{"bad compartment ocid", func(s *casv1alpha1.IssuerSpec) { s.CompartmentID = "ocid1.bucket.oc1.test" }, "compartmentId"},
		{"tenancy compartment ok", func(s *casv1alpha1.IssuerSpec) { s.CompartmentID = "ocid1.tenancy.oc1.test" }, ""},
		{"bad region", func(s *casv1alpha1.IssuerSpec) { s.Region = "ashburn" }, "region"},
		{"unsupported auth", func(s *casv1alpha1.IssuerSpec) { s.Auth.Type = casv1alpha1.AuthType("bad") }, "unsupported auth type"},
		{"api key missing ref", func(s *casv1alpha1.IssuerSpec) { s.Auth.Type = casv1alpha1.AuthTypeAPIKey }, "apiKeySecretRef.name"},
		{"api key empty name", func(s *casv1alpha1.IssuerSpec) {
			s.Auth.Type = casv1alpha1.AuthTypeAPIKey
			s.Auth.APIKeySecretRef = &casv1alpha1.SecretKeySelector{}
		}, "apiKeySecretRef.name"},
		{"api key ref with workload identity", func(s *casv1alpha1.IssuerSpec) {
			s.Auth.Type = casv1alpha1.AuthTypeWorkloadIdentity
			s.Auth.APIKeySecretRef = &casv1alpha1.SecretKeySelector{Name: "secret"}
		}, "apiKeySecretRef is only valid"},
		{"api key ref valid", func(s *casv1alpha1.IssuerSpec) {
			s.Auth.Type = casv1alpha1.AuthTypeAPIKey
			s.Auth.APIKeySecretRef = &casv1alpha1.SecretKeySelector{Name: "secret"}
		}, ""},
		{"instance principal valid", func(s *casv1alpha1.IssuerSpec) { s.Auth.Type = casv1alpha1.AuthTypeInstancePrincipal }, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := valid
			tt.mut(&spec)
			err := validateIssuerSpec(spec)
			if tt.want == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.want)
		})
	}
}

func TestValidateCertificateRequest(t *testing.T) {
	validCSR, key := csrForValidation(t, pkix.Name{CommonName: "example.com"}, []string{"example.com"}, nil, nil, nil)
	validDetails := signer.CertificateDetails{CSR: validCSR, Duration: 24 * time.Hour}
	parsed, err := validateCertificateRequest(validDetails)
	require.NoError(t, err)
	require.Equal(t, "example.com", parsed.CSR.Subject.CommonName)

	wrongBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("bad")})
	_, err = validateCertificateRequest(signer.CertificateDetails{CSR: wrongBlock, Duration: 24 * time.Hour})
	require.ErrorContains(t, err, "PEM encoded CSR")

	_, err = validateCertificateRequest(signer.CertificateDetails{CSR: []byte("not pem"), Duration: 24 * time.Hour})
	require.ErrorContains(t, err, "PEM encoded CSR")

	_, err = validateCertificateRequest(signer.CertificateDetails{CSR: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("bad")}), Duration: 24 * time.Hour})
	require.ErrorContains(t, err, "parse CSR")

	block, _ := pem.Decode(validCSR)
	require.NotNil(t, block)
	corrupt := append([]byte(nil), block.Bytes...)
	corrupt[len(corrupt)-1] ^= 0xff
	_, err = validateCertificateRequest(signer.CertificateDetails{CSR: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: corrupt}), Duration: 24 * time.Hour})
	require.ErrorContains(t, err, "CSR signature")

	emptyCN, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"example.com"}}, key)
	_, err = validateCertificateRequest(signer.CertificateDetails{CSR: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: emptyCN}), Duration: 24 * time.Hour})
	require.ErrorContains(t, err, requiredCommonNameMsg)

	unsupportedSANs, _ := csrForValidation(t,
		pkix.Name{CommonName: "example.com"},
		[]string{"example.com"},
		[]net.IP{net.ParseIP("10.0.0.1")},
		[]*url.URL{mustURL(t, "spiffe://example.com/app")},
		[]string{"admin@example.com"},
	)
	_, err = validateCertificateRequest(signer.CertificateDetails{CSR: unsupportedSANs, Duration: 24 * time.Hour})
	require.ErrorContains(t, err, "DNS SANs only")

	_, err = validateCertificateRequest(signer.CertificateDetails{CSR: validCSR, Duration: time.Minute})
	require.ErrorContains(t, err, "at least")

	_, err = validateCertificateRequest(signer.CertificateDetails{CSR: validCSR, Duration: maxRequestDuration + time.Hour})
	require.ErrorContains(t, err, "no more")

	_, err = validateCertificateRequest(signer.CertificateDetails{CSR: validCSR, Duration: 24 * time.Hour, IsCA: true})
	require.ErrorContains(t, err, "CA certificate requests")
}

func TestValidateIssuedCertificateSuccess(t *testing.T) {
	csrPEM, key := csrForValidation(t,
		pkix.Name{
			CommonName:         "example.com",
			Organization:       []string{"Example Inc"},
			OrganizationalUnit: []string{"Platform"},
			Country:            []string{"US"},
			Locality:           []string{"Atlanta"},
			Province:           []string{"Georgia"},
			StreetAddress:      []string{"123 Main St"},
			PostalCode:         []string{"30301"},
			SerialNumber:       "app-001",
		},
		[]string{"example.com", "www.example.com"},
		[]net.IP{net.ParseIP("10.0.0.1")},
		[]*url.URL{mustURL(t, "spiffe://example.com/app")},
		[]string{"admin@example.com"},
	)
	csr := parseCSR(t, csrPEM)
	leaf := leafForValidation(t, csr, key, func(cert *x509.Certificate) {
		cert.Subject.Country = []string{"us"}
		cert.Subject.PostalCode = nil
	})
	details := signer.CertificateDetails{
		CSR:         csrPEM,
		Duration:    24 * time.Hour,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	require.NoError(t, validateIssuedCertificate(csr, details, []*x509.Certificate{leaf}, time.Now().UTC()))
}

func TestValidateIssuedCertificateVerifiesReturnedChain(t *testing.T) {
	caCert, caKey := testCA(t)
	otherCA, _ := testCA(t)
	csrPEM := testCSR(t)
	csr := parseCSR(t, csrPEM)
	leafPEM := signCSR(t, csrPEM, caCert, caKey)
	leaf := parseCertificatePEM(t, leafPEM)
	details := signer.CertificateDetails{
		CSR:         csrPEM,
		Duration:    24 * time.Hour,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	require.NoError(t, validateIssuedCertificate(csr, details, []*x509.Certificate{leaf, caCert}, time.Now().UTC()))
	err := validateIssuedCertificate(csr, details, []*x509.Certificate{leaf, otherCA}, time.Now().UTC())
	require.ErrorContains(t, err, "verify issued certificate chain")
}

func TestValidateIssuedCertificateFailures(t *testing.T) {
	csrPEM, key := csrForValidation(t, pkix.Name{CommonName: "example.com"}, []string{"example.com"}, nil, nil, nil)
	csr := parseCSR(t, csrPEM)
	details := signer.CertificateDetails{
		CSR:         csrPEM,
		Duration:    24 * time.Hour,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	requestStart := time.Now().UTC()

	tests := []struct {
		name string
		cert *x509.Certificate
		want string
	}{
		{"public key mismatch", leafForValidation(t, csr, newRSAKey(t), func(*x509.Certificate) {}), "public key"},
		{"subject mismatch", leafForValidation(t, csr, key, func(c *x509.Certificate) { c.Subject.CommonName = "other.example.com" }), "subject"},
		{"dns mismatch", leafForValidation(t, csr, key, func(c *x509.Certificate) { c.DNSNames = []string{"other.example.com"} }), "DNS"},
		{"future notBefore", leafForValidation(t, csr, key, func(c *x509.Certificate) { c.NotBefore = time.Now().Add(2 * time.Minute) }), "future"},
		{"stale notBefore", leafForValidation(t, csr, key, func(c *x509.Certificate) { c.NotBefore = time.Now().Add(-30 * time.Minute) }), "past"},
		{"wrong notAfter", leafForValidation(t, csr, key, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(2 * time.Hour) }), "notAfter"},
		{"ca leaf", leafForValidation(t, csr, key, func(c *x509.Certificate) {
			c.IsCA = true
			c.BasicConstraintsValid = true
		}), "CA certificate"},
		{"missing key usage", leafForValidation(t, csr, key, func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature }), "key usages"},
		{"missing ext key usage", leafForValidation(t, csr, key, func(c *x509.Certificate) { c.ExtKeyUsage = nil }), "extended key usages"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIssuedCertificate(csr, details, []*x509.Certificate{tt.cert}, requestStart)
			require.ErrorContains(t, err, tt.want)
		})
	}

	err := validateIssuedCertificate(csr, details, nil, requestStart)
	require.ErrorContains(t, err, "leaf certificate")
}

func TestValidateSANFailuresAndSetHelpers(t *testing.T) {
	csrPEM, key := csrForValidation(t,
		pkix.Name{CommonName: "example.com"},
		[]string{"example.com"},
		[]net.IP{net.ParseIP("10.0.0.1")},
		[]*url.URL{mustURL(t, "spiffe://example.com/app")},
		[]string{"admin@example.com"},
	)
	csr := parseCSR(t, csrPEM)
	base := func(mut func(*x509.Certificate)) *x509.Certificate {
		return leafForValidation(t, csr, key, mut)
	}
	require.ErrorContains(t, validateSANs(csr, base(func(c *x509.Certificate) { c.IPAddresses = nil })), "IP")
	require.ErrorContains(t, validateSANs(csr, base(func(c *x509.Certificate) { c.URIs = nil })), "URI")
	require.ErrorContains(t, validateSANs(csr, base(func(c *x509.Certificate) { c.EmailAddresses = nil })), "email")

	require.True(t, equalIPSet([]net.IP{net.ParseIP("10.0.0.1")}, []net.IP{net.ParseIP("10.0.0.1")}))
	require.False(t, equalIPSet([]net.IP{net.ParseIP("10.0.0.1")}, []net.IP{net.ParseIP("10.0.0.2")}))
	require.True(t, equalURISet([]*url.URL{mustURL(t, "spiffe://example.com/app")}, []*url.URL{mustURL(t, "spiffe://example.com/app")}))
	require.False(t, equalURISet([]*url.URL{mustURL(t, "spiffe://example.com/app")}, []*url.URL{mustURL(t, "spiffe://example.com/other")}))
	require.False(t, containsAllExtKeyUsages([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}))
}

func TestDecodeCertificateChainPEM(t *testing.T) {
	csrPEM, key := csrForValidation(t, pkix.Name{CommonName: "example.com"}, []string{"example.com"}, nil, nil, nil)
	leaf := leafForValidation(t, parseCSR(t, csrPEM), key, func(*x509.Certificate) {})
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	certs, err := decodeCertificateChainPEM(leafPEM)
	require.NoError(t, err)
	require.Len(t, certs, 1)

	_, err = decodeCertificateChainPEM(nil)
	require.ErrorContains(t, err, "no certificates")
	_, err = decodeCertificateChainPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("bad")}))
	require.ErrorContains(t, err, "unexpected PEM block")
	_, err = decodeCertificateChainPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("bad")}))
	require.ErrorContains(t, err, "parse certificate")
	_, err = decodeCertificateChainPEM(append(leafPEM, []byte("trailing")...))
	require.ErrorContains(t, err, "trailing")
}

func TestValidatePublicKeyMarshalErrors(t *testing.T) {
	csrPEM, key := csrForValidation(t, pkix.Name{CommonName: "example.com"}, []string{"example.com"}, nil, nil, nil)
	csr := parseCSR(t, csrPEM)
	leaf := leafForValidation(t, csr, key, func(*x509.Certificate) {})

	badCSR := *csr
	badCSR.PublicKey = "bad"
	require.ErrorContains(t, validatePublicKey(&badCSR, leaf), "CSR public key")

	badLeaf := *leaf
	badLeaf.PublicKey = "bad"
	require.ErrorContains(t, validatePublicKey(csr, &badLeaf), "issued certificate public key")
}

func csrForValidation(t *testing.T, subject pkix.Name, dns []string, ips []net.IP, uris []*url.URL, emails []string) ([]byte, crypto.Signer) {
	t.Helper()
	key := newRSAKey(t)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:        subject,
		DNSNames:       dns,
		IPAddresses:    ips,
		URIs:           uris,
		EmailAddresses: emails,
	}, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), key
}

func parseCSR(t *testing.T, csrPEM []byte) *x509.CertificateRequest {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	require.NotNil(t, block)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	return csr
}

func parseCertificatePEM(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

func leafForValidation(t *testing.T, csr *x509.CertificateRequest, key crypto.Signer, mutate func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               csr.Subject,
		DNSNames:              append([]string(nil), csr.DNSNames...),
		IPAddresses:           append([]net.IP(nil), csr.IPAddresses...),
		URIs:                  append([]*url.URL(nil), csr.URIs...),
		EmailAddresses:        append([]string(nil), csr.EmailAddresses...),
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	mutate(tmpl)
	ca, caKey := testCA(t)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func newRSAKey(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

func mustURL(t *testing.T, value string) *url.URL {
	t.Helper()
	u, err := url.Parse(value)
	require.NoError(t, err)
	return u
}
