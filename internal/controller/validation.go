package controller

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/cert-manager/issuer-lib/controllers/signer"

	casv1alpha1 "github.com/oci-cert-manager/oci-cas-issuer/api/v1alpha1"
)

const (
	minRequestDuration    = time.Hour
	maxRequestDuration    = 397 * 24 * time.Hour
	notBeforeFutureSkew   = time.Minute
	notBeforeStaleSkew    = 15 * time.Minute
	notAfterAllowedDrift  = 2 * time.Minute
	requiredCommonNameMsg = "CSR subject common name is required by OCI Certificates Management"
)

var (
	certificateAuthorityOCIDPattern = regexp.MustCompile(`^ocid1\.certificateauthority\.`)
	compartmentOCIDPattern          = regexp.MustCompile(`^ocid1\.(compartment|tenancy)\.`)
	regionPattern                   = regexp.MustCompile(`^[a-z]+-[a-z]+-[0-9]+$`)
)

type validatedRequest struct {
	CSR      *x509.CertificateRequest
	Duration time.Duration
	IsCA     bool
}

func validateIssuerSpec(spec casv1alpha1.IssuerSpec) error {
	if !certificateAuthorityOCIDPattern.MatchString(spec.CertificateAuthorityID) {
		return fmt.Errorf("certificateAuthorityId must be an OCI certificate authority OCID")
	}
	if !compartmentOCIDPattern.MatchString(spec.CompartmentID) {
		return fmt.Errorf("compartmentId must be an OCI compartment or tenancy OCID")
	}
	if !regionPattern.MatchString(spec.Region) {
		return fmt.Errorf("region must look like an OCI region, for example us-ashburn-1")
	}

	authType := spec.Auth.Type
	if authType == "" {
		authType = casv1alpha1.AuthTypeWorkloadIdentity
	}
	switch authType {
	case casv1alpha1.AuthTypeWorkloadIdentity, casv1alpha1.AuthTypeInstancePrincipal:
		if spec.Auth.APIKeySecretRef != nil {
			return fmt.Errorf("apiKeySecretRef is only valid when auth.type is apiKey")
		}
	case casv1alpha1.AuthTypeAPIKey:
		if spec.Auth.APIKeySecretRef == nil || spec.Auth.APIKeySecretRef.Name == "" {
			return fmt.Errorf("apiKey auth requires apiKeySecretRef.name")
		}
	default:
		return fmt.Errorf("unsupported auth type %q", authType)
	}
	return nil
}

func validateCertificateRequest(details signer.CertificateDetails) (validatedRequest, error) {
	block, _ := pem.Decode(details.CSR)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return validatedRequest{}, fmt.Errorf("request is not a PEM encoded CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return validatedRequest{}, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return validatedRequest{}, fmt.Errorf("CSR signature is invalid: %w", err)
	}
	if csr.Subject.CommonName == "" {
		return validatedRequest{}, errors.New(requiredCommonNameMsg)
	}
	if len(csr.IPAddresses) > 0 || len(csr.URIs) > 0 || len(csr.EmailAddresses) > 0 {
		return validatedRequest{}, fmt.Errorf("OCI Certificates Management external CSR signing currently supports DNS SANs only")
	}
	if details.Duration < minRequestDuration {
		return validatedRequest{}, fmt.Errorf("requested duration must be at least %s", minRequestDuration)
	}
	if details.Duration > maxRequestDuration {
		return validatedRequest{}, fmt.Errorf("requested duration must be no more than %s", maxRequestDuration)
	}
	if details.IsCA {
		return validatedRequest{}, fmt.Errorf("CA certificate requests are not supported")
	}
	return validatedRequest{CSR: csr, Duration: details.Duration, IsCA: details.IsCA}, nil
}

func validateIssuedCertificate(csr *x509.CertificateRequest, details signer.CertificateDetails, certs []*x509.Certificate, requestStart time.Time) error {
	if len(certs) == 0 {
		return fmt.Errorf("OCI certificate bundle did not contain a leaf certificate")
	}
	leaf := certs[0]
	if err := validatePublicKey(csr, leaf); err != nil {
		return err
	}
	if !equalOCISubject(csr.Subject, leaf.Subject) {
		return fmt.Errorf("issued certificate subject does not match CSR subject")
	}
	if err := validateSANs(csr, leaf); err != nil {
		return err
	}
	if err := validateValidity(leaf, requestStart.UTC(), details.Duration); err != nil {
		return err
	}
	if err := validateCertificateChain(certs, requestStart.UTC()); err != nil {
		return err
	}
	if leaf.IsCA {
		return fmt.Errorf("issued certificate is a CA certificate")
	}
	if leaf.KeyUsage&details.KeyUsage != details.KeyUsage {
		return fmt.Errorf("issued certificate is missing requested key usages")
	}
	if !containsAllExtKeyUsages(leaf.ExtKeyUsage, details.ExtKeyUsage) {
		return fmt.Errorf("issued certificate is missing requested extended key usages")
	}
	return nil
}

func decodeCertificateChainPEM(chainPEM []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := chainPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block %q in certificate bundle", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate bundle: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, fmt.Errorf("certificate bundle contains trailing non-PEM data")
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("certificate bundle contains no certificates")
	}
	return certs, nil
}

func validateCertificateChain(certs []*x509.Certificate, requestStart time.Time) error {
	if len(certs) < 2 {
		return nil
	}

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		roots.AddCert(cert)
		intermediates.AddCert(cert)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   requestStart,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("verify issued certificate chain: %w", err)
	}
	return nil
}

func validatePublicKey(csr *x509.CertificateRequest, leaf *x509.Certificate) error {
	csrKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal CSR public key: %w", err)
	}
	leafKey, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal issued certificate public key: %w", err)
	}
	if !bytes.Equal(csrKey, leafKey) {
		return fmt.Errorf("issued certificate public key does not match CSR public key")
	}
	return nil
}

func equalOCISubject(csr, leaf pkix.Name) bool {
	return csr.CommonName == leaf.CommonName &&
		slices.Equal(csr.Organization, leaf.Organization) &&
		slices.Equal(csr.OrganizationalUnit, leaf.OrganizationalUnit) &&
		slices.Equal(lowercaseStrings(csr.Country), lowercaseStrings(leaf.Country)) &&
		slices.Equal(csr.Locality, leaf.Locality) &&
		slices.Equal(csr.Province, leaf.Province) &&
		slices.Equal(csr.StreetAddress, leaf.StreetAddress) &&
		csr.SerialNumber == leaf.SerialNumber
}

func lowercaseStrings(values []string) []string {
	out := append([]string(nil), values...)
	for i, value := range out {
		out[i] = strings.ToLower(value)
	}
	return out
}

func validateSANs(csr *x509.CertificateRequest, leaf *x509.Certificate) error {
	if !equalStringSet(csr.DNSNames, leaf.DNSNames) {
		return fmt.Errorf("issued certificate DNS SANs do not match CSR")
	}
	if !equalIPSet(csr.IPAddresses, leaf.IPAddresses) {
		return fmt.Errorf("issued certificate IP SANs do not match CSR")
	}
	if !equalURISet(csr.URIs, leaf.URIs) {
		return fmt.Errorf("issued certificate URI SANs do not match CSR")
	}
	if !equalStringSet(csr.EmailAddresses, leaf.EmailAddresses) {
		return fmt.Errorf("issued certificate email SANs do not match CSR")
	}
	return nil
}

func validateValidity(leaf *x509.Certificate, requestStart time.Time, duration time.Duration) error {
	validationNow := time.Now().UTC()
	if leaf.NotBefore.After(validationNow.Add(notBeforeFutureSkew)) {
		return fmt.Errorf("issued certificate notBefore is in the future")
	}
	if leaf.NotBefore.Before(validationNow.Add(-notBeforeStaleSkew)) {
		return fmt.Errorf("issued certificate notBefore is too far in the past")
	}
	expectedNotAfter := requestStart.Add(duration)
	if leaf.NotAfter.Before(expectedNotAfter.Add(-notAfterAllowedDrift)) || leaf.NotAfter.After(expectedNotAfter.Add(notAfterAllowedDrift)) {
		return fmt.Errorf("issued certificate notAfter %s does not match requested duration ending near %s", leaf.NotAfter.UTC().Format(time.RFC3339), expectedNotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

func containsAllExtKeyUsages(actual, requested []x509.ExtKeyUsage) bool {
	for _, want := range requested {
		if !slices.Contains(actual, want) {
			return false
		}
	}
	return true
}

func equalStringSet(a, b []string) bool {
	return slices.Equal(sortedStrings(a), sortedStrings(b))
}

func sortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	slices.Sort(out)
	return out
}

func equalIPSet(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	left := make([]string, 0, len(a))
	right := make([]string, 0, len(b))
	for _, value := range a {
		left = append(left, value.String())
	}
	for _, value := range b {
		right = append(right, value.String())
	}
	return equalStringSet(left, right)
}

func equalURISet(a, b []*url.URL) bool {
	if len(a) != len(b) {
		return false
	}
	left := make([]string, 0, len(a))
	right := make([]string, 0, len(b))
	for _, value := range a {
		left = append(left, value.String())
	}
	for _, value := range b {
		right = append(right, value.String())
	}
	return equalStringSet(left, right)
}
