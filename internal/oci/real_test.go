package oci

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/certificates"
	certsmgmt "github.com/oracle/oci-go-sdk/v65/certificatesmanagement"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/stretchr/testify/require"
)

type serviceError struct {
	status  int
	message string
}

func (e serviceError) Error() string           { return fmt.Sprintf("status %d", e.status) }
func (e serviceError) GetHTTPStatusCode() int  { return e.status }
func (e serviceError) GetMessage() string      { return e.message }
func (e serviceError) GetCode() string         { return "code" }
func (e serviceError) GetOpcRequestID() string { return "request" }

var _ common.ServiceError = serviceError{}

func TestClassify(t *testing.T) {
	tests := []struct {
		status int
		target error
	}{
		{404, ErrNotFound},
		{409, ErrConflict},
		{400, ErrInvalid},
		{422, ErrInvalid},
		{401, ErrUnauthorized},
		{403, ErrUnauthorized},
		{429, ErrRetryable},
		{500, ErrRetryable},
		{502, ErrRetryable},
		{503, ErrRetryable},
		{504, ErrRetryable},
	}
	for _, tt := range tests {
		err := classify(serviceError{status: tt.status})
		require.ErrorIs(t, err, tt.target)
	}
	require.NoError(t, classify(nil))
	raw := errors.New("raw")
	require.Same(t, raw, classify(raw))
	require.NotErrorIs(t, classify(serviceError{status: 418}), ErrRetryable)
	require.ErrorIs(t, classify(serviceError{status: 400, message: "A certificate with the name already exists."}), ErrConflict)
}

func TestValue(t *testing.T) {
	require.Empty(t, value(nil))
	s := "value"
	require.Equal(t, "value", value(&s))
}

func TestCreateCertificateDetails(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	details := createCertificateDetails(IssueRequest{
		CompartmentID:          "compartment",
		CertificateAuthorityID: "ca",
		Name:                   "name",
		CSRPem:                 "csr",
		ValidityDuration:       36 * time.Hour,
		Tags:                   map[string]string{"managed": "true"},
	}, func() time.Time { return now })

	require.Equal(t, "name", value(details.Name))
	require.Equal(t, "compartment", value(details.CompartmentId))
	require.Equal(t, map[string]string{"managed": "true"}, details.FreeformTags)
	config, ok := details.CertificateConfig.(createManagedExternallyIssuedByInternalCAConfig)
	require.True(t, ok)
	require.Equal(t, "ca", value(config.IssuerCertificateAuthorityId))
	require.Equal(t, "csr", value(config.CsrPem))
	require.Equal(t, "name", value(config.VersionName))
	require.Equal(t, "name", value(config.GetVersionName()))
	require.Equal(t, "2026-06-03T11:55:00.000+00:00", config.Validity.TimeOfValidityNotBefore)
	require.Equal(t, "2026-06-05T00:00:00.000+00:00", config.Validity.TimeOfValidityNotAfter)

	payload, err := json.Marshal(config)
	require.NoError(t, err)
	require.JSONEq(t, `{
		"configType":"MANAGED_EXTERNALLY_ISSUED_BY_INTERNAL_CA",
		"issuerCertificateAuthorityId":"ca",
		"csrPem":"csr",
		"versionName":"name",
		"validity":{
			"timeOfValidityNotBefore":"2026-06-03T11:55:00.000+00:00",
			"timeOfValidityNotAfter":"2026-06-05T00:00:00.000+00:00"
		}
	}`, string(payload))

	details = createCertificateDetails(IssueRequest{Name: "name"}, func() time.Time { return now })
	config, ok = details.CertificateConfig.(createManagedExternallyIssuedByInternalCAConfig)
	require.True(t, ok)
	require.Nil(t, config.Validity)
}

func TestFormatOCITime(t *testing.T) {
	require.Equal(t, "2026-06-03T12:00:00.000+00:00", formatOCITime(time.Date(2026, 6, 3, 8, 0, 0, 0, time.FixedZone("EDT", -4*60*60))))
}

func TestCertificateResourceMappers(t *testing.T) {
	cert := certificateResource(certsmgmt.Certificate{
		Id:             common.String("id"),
		Name:           common.String("name"),
		LifecycleState: certsmgmt.CertificateLifecycleStateActive,
		FreeformTags:   map[string]string{"managed": "true"},
	})
	require.Equal(t, CertificateResource{
		ID:             "id",
		Name:           "name",
		LifecycleState: LifecycleActive,
		Tags:           map[string]string{"managed": "true"},
	}, cert)

	summary := certificateSummaryResource(certsmgmt.CertificateSummary{
		Id:             common.String("summary-id"),
		Name:           common.String("summary"),
		LifecycleState: certsmgmt.CertificateLifecycleStateCreating,
		FreeformTags:   map[string]string{"managed": "true"},
	})
	require.Equal(t, "summary-id", summary.ID)
	require.Equal(t, LifecycleCreating, summary.LifecycleState)
}

func TestNewRealClient(t *testing.T) {
	client := newTestRealClient(t)
	require.Contains(t, client.management.Host, "us-phoenix-1")
	require.Contains(t, client.retrieval.Host, "us-phoenix-1")

	_, err := NewRealClient(common.NewRawConfigurationProvider("", "", "", "", "", nil), "")
	require.Error(t, err)
}

func TestNewRealClientConstructorErrors(t *testing.T) {
	provider := common.NewRawConfigurationProvider("tenancy", "user", "region", "fingerprint", "key", nil)
	_, err := newRealClient(provider, "", sdkClientConstructors{
		management: func(common.ConfigurationProvider) (certsmgmt.CertificatesManagementClient, error) {
			return certsmgmt.CertificatesManagementClient{}, errors.New("management")
		},
		retrieval: func(common.ConfigurationProvider) (certificates.CertificatesClient, error) {
			return certificates.CertificatesClient{}, nil
		},
	})
	require.ErrorContains(t, err, "management")

	_, err = newRealClient(provider, "", sdkClientConstructors{
		management: func(common.ConfigurationProvider) (certsmgmt.CertificatesManagementClient, error) {
			return certsmgmt.CertificatesManagementClient{}, nil
		},
		retrieval: func(common.ConfigurationProvider) (certificates.CertificatesClient, error) {
			return certificates.CertificatesClient{}, errors.New("retrieval")
		},
	})
	require.ErrorContains(t, err, "retrieval")
}

func TestRealClientHTTPMethods(t *testing.T) {
	dispatcher := &fakeDispatcher{}
	dispatcher.handler = func(r *http.Request) *http.Response {
		dispatcher.seen = append(dispatcher.seen, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/certificateAuthorities/"):
			return jsonResponse(http.StatusOK, `{"id":"ca","name":"ca","lifecycleState":"ACTIVE","compartmentId":"compartment","configType":"ROOT_CA_GENERATED_INTERNALLY","timeCreated":"2026-06-03T12:00:00Z"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/20210224/certificates":
			return jsonResponse(http.StatusOK, certificateJSON("cert", "cert", "ACTIVE"))
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/certificates/cert"):
			return jsonResponse(http.StatusOK, certificateJSON("cert", "cert", "ACTIVE"))
		case r.Method == http.MethodGet && r.URL.Path == "/20210224/certificates":
			return jsonResponse(http.StatusOK, `{"items":[`+certificateJSON("cert", "cert", "ACTIVE")+`]}`)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/certificateBundles/cert"):
			return jsonResponse(http.StatusOK, `{"certificateBundleType":"CERTIFICATE_CONTENT_PUBLIC_ONLY","certificateId":"cert","certificateName":"cert","versionNumber":1,"serialNumber":"01","timeCreated":"2026-06-03T12:00:00Z","validity":{"timeOfValidityNotBefore":"2026-06-03T12:00:00Z","timeOfValidityNotAfter":"2026-06-04T12:00:00Z"},"stages":["CURRENT"],"certificatePem":"leaf","certChainPem":"chain"}`)
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/actions/scheduleDeletion"):
			return jsonResponse(http.StatusOK, certificateJSON("cert", "cert", "PENDING_DELETION"))
		default:
			return jsonResponse(http.StatusNotFound, `{"code":"NotFound","message":"missing"}`)
		}
	}

	client := newTestRealClient(t)
	client.management.Host = "https://unit.test"
	client.retrieval.Host = "https://unit.test"
	client.management.HTTPClient = dispatcher
	client.retrieval.HTTPClient = dispatcher

	require.NoError(t, client.CheckCertificateAuthority(context.Background(), "ca"))
	cert, err := client.CreateCertificate(context.Background(), IssueRequest{Name: "cert", CompartmentID: "compartment", CertificateAuthorityID: "ca", CSRPem: "csr"})
	require.NoError(t, err)
	require.Equal(t, "cert", cert.ID)
	cert, err = client.GetCertificate(context.Background(), "cert")
	require.NoError(t, err)
	require.Equal(t, LifecycleActive, cert.LifecycleState)
	cert, err = client.FindCertificateByName(context.Background(), "compartment", "cert")
	require.NoError(t, err)
	require.Equal(t, "cert", cert.Name)
	_, err = client.FindCertificateByName(context.Background(), "compartment", "missing")
	require.ErrorIs(t, err, ErrNotFound)
	certs, err := client.ListManagedCertificates(context.Background(), "compartment")
	require.NoError(t, err)
	require.Len(t, certs, 1)
	bundle, err := client.GetCertificateBundle(context.Background(), "cert")
	require.NoError(t, err)
	require.Equal(t, "leaf", bundle.CertificatePEM)
	require.NoError(t, client.ScheduleCertificateDeletion(context.Background(), "cert", time.Now()))
	require.NotEmpty(t, dispatcher.seen)
}

func TestRealClientHTTPErrorClassification(t *testing.T) {
	client := newTestRealClient(t)
	client.management.Host = "https://unit.test"
	client.management.HTTPClient = &fakeDispatcher{handler: func(r *http.Request) *http.Response {
		return jsonResponse(http.StatusForbidden, `{"code":"NotAuthorizedOrNotFound","message":"nope"}`)
	}}
	err := client.CheckCertificateAuthority(context.Background(), "ca")
	require.ErrorIs(t, err, ErrUnauthorized)
}

func TestRealClientHTTPMethodErrors(t *testing.T) {
	client := newTestRealClient(t)
	client.management.Host = "https://unit.test"
	client.retrieval.Host = "https://unit.test"
	dispatcher := &fakeDispatcher{handler: func(r *http.Request) *http.Response {
		return jsonResponse(http.StatusServiceUnavailable, `{"code":"Unavailable","message":"retry"}`)
	}}
	client.management.HTTPClient = dispatcher
	client.retrieval.HTTPClient = dispatcher

	require.ErrorIs(t, client.CheckCertificateAuthority(context.Background(), "ca"), ErrRetryable)
	_, err := client.CreateCertificate(context.Background(), IssueRequest{})
	require.ErrorIs(t, err, ErrRetryable)
	_, err = client.GetCertificate(context.Background(), "cert")
	require.ErrorIs(t, err, ErrRetryable)
	_, err = client.FindCertificateByName(context.Background(), "compartment", "cert")
	require.ErrorIs(t, err, ErrRetryable)
	_, err = client.ListManagedCertificates(context.Background(), "compartment")
	require.ErrorIs(t, err, ErrRetryable)
	_, err = client.GetCertificateBundle(context.Background(), "cert")
	require.ErrorIs(t, err, ErrRetryable)
	require.ErrorIs(t, client.ScheduleCertificateDeletion(context.Background(), "cert", time.Now()), ErrRetryable)
}

func newTestRealClient(t *testing.T) *RealClient {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privateKey := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
	provider := common.NewRawConfigurationProvider(
		"ocid1.tenancy.oc1..aaaa",
		"ocid1.user.oc1..aaaa",
		"us-ashburn-1",
		"aa:bb:cc",
		privateKey,
		nil,
	)
	client, err := NewRealClient(provider, "us-phoenix-1")
	require.NoError(t, err)
	return client
}

func certificateJSON(id, name, state string) string {
	return fmt.Sprintf(`{"id":%q,"name":%q,"lifecycleState":%q,"compartmentId":"compartment","configType":"MANAGED_EXTERNALLY_ISSUED_BY_INTERNAL_CA","timeCreated":"2026-06-03T12:00:00Z","freeformTags":{"managed":"true"}}`, id, name, state)
}

type fakeDispatcher struct {
	seen    []string
	handler func(*http.Request) *http.Response
}

func (f *fakeDispatcher) Do(req *http.Request) (*http.Response, error) {
	resp := f.handler(req)
	resp.Request = req
	resp.Status = fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	return resp, nil
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
