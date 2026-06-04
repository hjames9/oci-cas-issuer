package controller

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	casv1alpha1 "github.com/oci-cert-manager/oci-cas-issuer/api/v1alpha1"
	ociissuer "github.com/oci-cert-manager/oci-cas-issuer/internal/oci"
)

type staticFactory struct {
	client ociissuer.Client
	err    error
}

func (f staticFactory) ForIssuer(context.Context, string, casv1alpha1.IssuerSpec) (ociissuer.Client, error) {
	return f.client, f.err
}

type noTagCreateClient struct {
	*ociissuer.FakeClient
}

func (c noTagCreateClient) CreateCertificate(context.Context, ociissuer.IssueRequest) (ociissuer.CertificateResource, error) {
	return ociissuer.CertificateResource{ID: "cert", Name: "oci-cas-request-uid", LifecycleState: ociissuer.LifecycleActive}, nil
}

type conflictMissingClient struct {
	*ociissuer.FakeClient
}

func (c conflictMissingClient) CreateCertificate(context.Context, ociissuer.IssueRequest) (ociissuer.CertificateResource, error) {
	return ociissuer.CertificateResource{}, ociissuer.ErrConflict
}

type listErrorClient struct {
	*ociissuer.FakeClient
}

func (c listErrorClient) ListManagedCertificates(context.Context, string) ([]ociissuer.CertificateResource, error) {
	return nil, ociissuer.ErrRetryable
}

type bareIssuer struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	conditions []metav1.Condition
}

func (b *bareIssuer) GetConditions() []metav1.Condition { return b.conditions }
func (b *bareIssuer) GetIssuerTypeIdentifier() string   { return "bare" }
func (b *bareIssuer) DeepCopyObject() runtime.Object    { return &bareIssuer{} }

type failingRequest struct {
	metav1.ObjectMeta
}

func (f failingRequest) GetCertificateDetails() (signer.CertificateDetails, error) {
	return signer.CertificateDetails{}, errors.New("details")
}

func (f failingRequest) GetConditions() []cmapi.CertificateRequestCondition {
	return nil
}

func TestSignCreatesOCICertificateAndReturnsBundle(t *testing.T) {
	caCert, caKey := testCA(t)
	csrPEM := testCSR(t)
	leafPEM := signCSR(t, csrPEM, caCert, caKey)

	fake := ociissuer.NewFakeClient()
	fake.Bundles["ocid1.certificate.oc1.test.oci-cas-request-uid"] = ociissuer.CertificateBundle{
		CertificatePEM: string(leafPEM),
		ChainPEM:       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})),
	}

	issuer := Issuer{ClientFactory: staticFactory{client: fake}}
	bundle, err := issuer.Sign(context.Background(), requestObject(csrPEM), issuerObject())
	require.NoError(t, err)
	require.NotEmpty(t, bundle.ChainPEM)
	require.NotEmpty(t, bundle.CAPEM)
	require.Len(t, fake.Created, 1)
	require.Equal(t, "oci-cas-request-uid", fake.Created[0].Name)
	require.Equal(t, []string{"ocid1.certificate.oc1.test.oci-cas-request-uid"}, fake.Deleted)
}

func TestSignReusesExistingCertificateOnConflict(t *testing.T) {
	caCert, caKey := testCA(t)
	csrPEM := testCSR(t)
	leafPEM := signCSR(t, csrPEM, caCert, caKey)

	fake := ociissuer.NewFakeClient()
	fake.Certificates["existing"] = ociissuer.CertificateResource{
		ID:             "existing",
		Name:           "oci-cas-request-uid",
		LifecycleState: ociissuer.LifecycleActive,
		Tags: map[string]string{
			tagManaged:          tagManagedValue,
			tagRequestUID:       "request-uid",
			tagRequestNamespace: "default",
			tagRequestName:      "request",
		},
	}
	fake.Bundles["existing"] = ociissuer.CertificateBundle{
		CertificatePEM: string(leafPEM),
		ChainPEM:       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})),
	}

	issuer := Issuer{ClientFactory: staticFactory{client: fake}}
	_, err := issuer.Sign(context.Background(), requestObject(csrPEM), issuerObject())
	require.NoError(t, err)
	require.Empty(t, fake.Created)
	require.Equal(t, []string{"existing"}, fake.Deleted)
}

func TestSignRejectsConflictingCertificateOwnedByDifferentRequest(t *testing.T) {
	fake := ociissuer.NewFakeClient()
	fake.Certificates["existing"] = ociissuer.CertificateResource{
		ID:             "existing",
		Name:           "oci-cas-request-uid",
		LifecycleState: ociissuer.LifecycleActive,
		Tags: map[string]string{
			tagManaged:          tagManagedValue,
			tagRequestUID:       "different",
			tagRequestNamespace: "default",
			tagRequestName:      "request",
		},
	}

	issuer := Issuer{ClientFactory: staticFactory{client: fake}}
	_, err := issuer.Sign(context.Background(), requestObject(testCSR(t)), issuerObject())
	require.Error(t, err)
	var permanent signer.PermanentError
	require.ErrorAs(t, err, &permanent)
	require.Empty(t, fake.Deleted)
}

func TestSignPendingWhenCertificateCreating(t *testing.T) {
	fake := ociissuer.NewFakeClient()
	fake.Certificates["pending"] = ociissuer.CertificateResource{
		ID:             "pending",
		Name:           "oci-cas-request-uid",
		LifecycleState: ociissuer.LifecycleCreating,
		Tags: map[string]string{
			tagManaged:          tagManagedValue,
			tagRequestUID:       "request-uid",
			tagRequestNamespace: "default",
			tagRequestName:      "request",
		},
	}
	issuer := Issuer{ClientFactory: staticFactory{client: fake}}
	_, err := issuer.Sign(context.Background(), requestObject(testCSR(t)), issuerObject())
	require.Error(t, err)
	var pending signer.PendingError
	require.ErrorAs(t, err, &pending)
}

func TestSignPendingForUnknownLifecycleAndGetErrors(t *testing.T) {
	for _, state := range []ociissuer.LifecycleState{"", "UPDATING"} {
		fake := ociissuer.NewFakeClient()
		fake.Certificates["pending"] = ownedResource("pending", state)
		issuer := Issuer{ClientFactory: staticFactory{client: fake}}
		_, err := issuer.Sign(context.Background(), requestObject(testCSR(t)), issuerObject())
		require.Error(t, err)
		var pending signer.PendingError
		require.ErrorAs(t, err, &pending)
	}

	fake := ociissuer.NewFakeClient()
	fake.Certificates["pending"] = ownedResource("missing", ociissuer.LifecycleCreating)
	issuer := Issuer{ClientFactory: staticFactory{client: fake}}
	_, err := issuer.Sign(context.Background(), requestObject(testCSR(t)), issuerObject())
	require.Error(t, err)
	var pending signer.PendingError
	require.ErrorAs(t, err, &pending)
}

func TestSignPermanentWhenCertificateFailed(t *testing.T) {
	fake := ociissuer.NewFakeClient()
	fake.Certificates["failed"] = ownedResource("failed", ociissuer.LifecycleFailed)
	issuer := Issuer{ClientFactory: staticFactory{client: fake}}
	_, err := issuer.Sign(context.Background(), requestObject(testCSR(t)), issuerObject())
	require.Error(t, err)
	var permanent signer.PermanentError
	require.ErrorAs(t, err, &permanent)
}

func TestSignRejectsInvalidCSR(t *testing.T) {
	issuer := Issuer{ClientFactory: staticFactory{client: ociissuer.NewFakeClient()}}
	_, err := issuer.Sign(context.Background(), requestObject([]byte("not a csr")), issuerObject())
	require.Error(t, err)
	var permanent signer.PermanentError
	require.ErrorAs(t, err, &permanent)
}

func TestSignIssuerAndFactoryErrors(t *testing.T) {
	issuer := Issuer{ClientFactory: staticFactory{client: ociissuer.NewFakeClient()}}
	_, err := issuer.Sign(context.Background(), requestObject(testCSR(t)), &bareIssuer{})
	require.Error(t, err)
	var issuerErr signer.IssuerError
	require.ErrorAs(t, err, &issuerErr)

	issuer = Issuer{ClientFactory: staticFactory{err: errors.New("factory")}}
	_, err = issuer.Sign(context.Background(), requestObject(testCSR(t)), issuerObject())
	require.ErrorAs(t, err, &issuerErr)

	badIssuer := issuerObject()
	badIssuer.Spec.Region = "bad"
	issuer = Issuer{ClientFactory: staticFactory{client: ociissuer.NewFakeClient()}}
	_, err = issuer.Sign(context.Background(), requestObject(testCSR(t)), badIssuer)
	require.ErrorAs(t, err, &issuerErr)
}

func TestSignCertificateDetailsError(t *testing.T) {
	issuer := Issuer{ClientFactory: staticFactory{client: ociissuer.NewFakeClient()}}
	_, err := issuer.Sign(context.Background(), &failingRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "request", Namespace: "default", UID: "uid"},
	}, issuerObject())
	require.Error(t, err)
	var permanent signer.PermanentError
	require.ErrorAs(t, err, &permanent)
}

func TestSignRejectsCreatedCertificateWithoutOwnershipTags(t *testing.T) {
	issuer := Issuer{ClientFactory: staticFactory{client: noTagCreateClient{FakeClient: ociissuer.NewFakeClient()}}}
	_, err := issuer.Sign(context.Background(), requestObject(testCSR(t)), issuerObject())
	require.Error(t, err)
	var permanent signer.PermanentError
	require.ErrorAs(t, err, &permanent)
}

func TestSignConflictThenFindMissingIsPending(t *testing.T) {
	issuer := Issuer{ClientFactory: staticFactory{client: conflictMissingClient{FakeClient: ociissuer.NewFakeClient()}}}
	_, err := issuer.Sign(context.Background(), requestObject(testCSR(t)), issuerObject())
	require.Error(t, err)
	var pending signer.PendingError
	require.ErrorAs(t, err, &pending)
}

func TestSignMapsOCIErrorClasses(t *testing.T) {
	tests := []struct {
		err    error
		assert func(*testing.T, error)
	}{
		{ociissuer.ErrRetryable, func(t *testing.T, err error) {
			var pending signer.PendingError
			require.ErrorAs(t, err, &pending)
		}},
		{ociissuer.ErrInvalid, func(t *testing.T, err error) {
			var permanent signer.PermanentError
			require.ErrorAs(t, err, &permanent)
		}},
		{ociissuer.ErrUnauthorized, func(t *testing.T, err error) {
			var issuerErr signer.IssuerError
			require.ErrorAs(t, err, &issuerErr)
		}},
		{errors.New("other"), func(t *testing.T, err error) {
			require.ErrorContains(t, err, "other")
		}},
	}

	for _, tt := range tests {
		fake := ociissuer.NewFakeClient()
		fake.CreateError = tt.err
		issuer := Issuer{ClientFactory: staticFactory{client: fake}}
		_, err := issuer.Sign(context.Background(), requestObject(testCSR(t)), issuerObject())
		require.Error(t, err)
		tt.assert(t, err)
	}
}

func TestSignMapsBundleErrorsAndParseErrors(t *testing.T) {
	fake := ociissuer.NewFakeClient()
	fake.BundleError = ociissuer.ErrRetryable
	issuer := Issuer{ClientFactory: staticFactory{client: fake}}
	_, err := issuer.Sign(context.Background(), requestObject(testCSR(t)), issuerObject())
	require.Error(t, err)
	var pending signer.PendingError
	require.ErrorAs(t, err, &pending)

	fake = ociissuer.NewFakeClient()
	fake.Bundles["ocid1.certificate.oc1.test.oci-cas-request-uid"] = ociissuer.CertificateBundle{
		CertificatePEM: "bad",
		ChainPEM:       "bad",
	}
	issuer = Issuer{ClientFactory: staticFactory{client: fake}}
	_, err = issuer.Sign(context.Background(), requestObject(testCSR(t)), issuerObject())
	require.Error(t, err)
	var permanent signer.PermanentError
	require.ErrorAs(t, err, &permanent)
}

func TestSignRejectsIssuedCertificateMismatch(t *testing.T) {
	caCert, caKey := testCA(t)
	csrPEM := testCSR(t)
	leafPEM := signCSRWithMutation(t, csrPEM, caCert, caKey, func(cert *x509.Certificate) {
		cert.DNSNames = []string{"other.example.com"}
	})

	fake := ociissuer.NewFakeClient()
	fake.Bundles["ocid1.certificate.oc1.test.oci-cas-request-uid"] = ociissuer.CertificateBundle{
		CertificatePEM: string(leafPEM),
		ChainPEM:       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})),
	}

	issuer := Issuer{ClientFactory: staticFactory{client: fake}}
	_, err := issuer.Sign(context.Background(), requestObject(csrPEM), issuerObject())
	require.Error(t, err)
	var permanent signer.PermanentError
	require.ErrorAs(t, err, &permanent)
}

func TestSignRejectsBrokenReturnedChain(t *testing.T) {
	caCert, caKey := testCA(t)
	otherCA, _ := testCA(t)
	csrPEM := testCSR(t)
	leafPEM := signCSR(t, csrPEM, caCert, caKey)

	fake := ociissuer.NewFakeClient()
	fake.Bundles["ocid1.certificate.oc1.test.oci-cas-request-uid"] = ociissuer.CertificateBundle{
		CertificatePEM: string(leafPEM),
		ChainPEM:       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherCA.Raw})),
	}

	issuer := Issuer{ClientFactory: staticFactory{client: fake}}
	_, err := issuer.Sign(context.Background(), requestObject(csrPEM), issuerObject())
	require.Error(t, err)
	var permanent signer.PermanentError
	require.ErrorAs(t, err, &permanent)
}

func TestSignRejectsReturnedBundleWithExtraUnrelatedCertificate(t *testing.T) {
	caCert, caKey := testCA(t)
	otherCA, _ := testCA(t)
	csrPEM := testCSR(t)
	leafPEM := signCSR(t, csrPEM, caCert, caKey)

	fake := ociissuer.NewFakeClient()
	fake.Bundles["ocid1.certificate.oc1.test.oci-cas-request-uid"] = ociissuer.CertificateBundle{
		CertificatePEM: string(leafPEM),
		ChainPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})) +
			string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherCA.Raw})),
	}

	issuer := Issuer{ClientFactory: staticFactory{client: fake}}
	_, err := issuer.Sign(context.Background(), requestObject(csrPEM), issuerObject())
	require.Error(t, err)
	var permanent signer.PermanentError
	require.ErrorAs(t, err, &permanent)
	require.ErrorContains(t, err, "parse OCI certificate bundle")
}

func TestSignReturnsBundleWhenCleanupFails(t *testing.T) {
	caCert, caKey := testCA(t)
	csrPEM := testCSR(t)
	leafPEM := signCSR(t, csrPEM, caCert, caKey)

	fake := ociissuer.NewFakeClient()
	fake.DeleteError = ociissuer.ErrRetryable
	fake.Bundles["ocid1.certificate.oc1.test.oci-cas-request-uid"] = ociissuer.CertificateBundle{
		CertificatePEM: string(leafPEM),
		ChainPEM:       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})),
	}

	issuer := Issuer{ClientFactory: staticFactory{client: fake}}
	bundle, err := issuer.Sign(context.Background(), requestObject(csrPEM), issuerObject())
	require.NoError(t, err)
	require.NotEmpty(t, bundle.ChainPEM)
}

func TestGarbageCollectorSchedulesOnlyManagedCertificates(t *testing.T) {
	fake := ociissuer.NewFakeClient()
	fake.Certificates["managed"] = ociissuer.CertificateResource{
		ID: "managed",
		Tags: map[string]string{
			tagManaged: tagManagedValue,
		},
	}
	fake.Certificates["unmanaged"] = ociissuer.CertificateResource{
		ID:   "unmanaged",
		Tags: map[string]string{},
	}

	count, err := (GarbageCollector{
		Client:      fake,
		Compartment: "ocid1.compartment.oc1.test",
		DeleteAfter: time.Minute,
		Now:         func() time.Time { return time.Unix(100, 0) },
	}).RunOnce(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, count)
	require.Equal(t, []string{"managed"}, fake.Deleted)
}

func TestCheckReturnsPermanentForMissingCA(t *testing.T) {
	fake := ociissuer.NewFakeClient()
	fake.CAError = ociissuer.ErrNotFound
	issuer := Issuer{ClientFactory: staticFactory{client: fake}}
	err := issuer.Check(context.Background(), issuerObject())
	require.Error(t, err)
	var permanent signer.PermanentError
	require.ErrorAs(t, err, &permanent)
}

func TestCheckSuccessRetryableAndFactoryError(t *testing.T) {
	issuer := Issuer{ClientFactory: staticFactory{client: ociissuer.NewFakeClient()}}
	require.NoError(t, issuer.Check(context.Background(), issuerObject()))

	fake := ociissuer.NewFakeClient()
	fake.CAError = ociissuer.ErrRetryable
	issuer = Issuer{ClientFactory: staticFactory{client: fake}}
	require.ErrorIs(t, issuer.Check(context.Background(), issuerObject()), ociissuer.ErrRetryable)

	issuer = Issuer{ClientFactory: staticFactory{err: errors.New("factory")}}
	err := issuer.Check(context.Background(), issuerObject())
	require.Error(t, err)
	var permanent signer.PermanentError
	require.ErrorAs(t, err, &permanent)

	err = issuer.Check(context.Background(), &bareIssuer{})
	require.ErrorAs(t, err, &permanent)

	badIssuer := issuerObject()
	badIssuer.Spec.Region = "bad"
	err = issuer.Check(context.Background(), badIssuer)
	require.ErrorAs(t, err, &permanent)
}

func TestIssuerDetails(t *testing.T) {
	issuer := Issuer{ClusterResourceNamespace: "cluster-secrets"}
	spec, namespace, err := issuer.issuerDetails(issuerObject())
	require.NoError(t, err)
	require.Equal(t, "default", namespace)
	require.Equal(t, "ocid1.compartment.oc1.test", spec.CompartmentID)

	spec, namespace, err = issuer.issuerDetails(&casv1alpha1.OCIClusterIssuer{Spec: issuerObject().Spec})
	require.NoError(t, err)
	require.Equal(t, "cluster-secrets", namespace)
	require.Equal(t, "ocid1.compartment.oc1.test", spec.CompartmentID)

	_, _, err = issuer.issuerDetails(&bareIssuer{})
	require.Error(t, err)
	var permanent signer.PermanentError
	require.ErrorAs(t, err, &permanent)
}

func TestHelpers(t *testing.T) {
	require.Equal(t, "oci-cas-abc", certificateName(types.UID("abc")))
	require.LessOrEqual(t, len(certificateName(types.UID("0c37eda5-9077-4a3f-8360-787c4582c4b1"))), 50)

	require.Equal(t, "cluster", APIKeySecretNamespace("OCIClusterIssuer", "issuer", "cluster"))
	require.Equal(t, "issuer", APIKeySecretNamespace("OCIIssuer", "issuer", "cluster"))

	cr := requestObject(testCSR(t))
	tags := requestTags(cr)
	require.True(t, ownedByRequest(ociissuer.CertificateResource{Tags: tags}, cr))
	tags[tagRequestUID] = "other"
	require.False(t, ownedByRequest(ociissuer.CertificateResource{Tags: tags}, cr))

	require.Equal(t, DefaultCleanupPolicy(), cleanupPolicy(CleanupPolicy{}))
	custom := CleanupPolicy{DeleteAfter: time.Minute}
	require.Equal(t, custom, cleanupPolicy(custom))
}

func TestScheduleDeletion(t *testing.T) {
	fake := ociissuer.NewFakeClient()
	now := func() time.Time { return time.Unix(100, 0) }
	require.NoError(t, scheduleDeletion(context.Background(), fake, CleanupPolicy{}, "cert", now))
	require.Equal(t, []string{"cert"}, fake.Deleted)

	fake.DeleteError = ociissuer.ErrRetryable
	err := scheduleDeletion(context.Background(), fake, CleanupPolicy{DeleteAfter: time.Minute}, "cert", now)
	require.ErrorIs(t, err, ociissuer.ErrRetryable)
}

func TestGarbageCollectorBranches(t *testing.T) {
	count, err := (GarbageCollector{}).RunOnce(context.Background())
	require.NoError(t, err)
	require.Zero(t, count)

	fake := ociissuer.NewFakeClient()
	fake.Certificates["managed"] = ociissuer.CertificateResource{
		ID:   "managed",
		Tags: map[string]string{tagManaged: tagManagedValue},
	}
	fake.DeleteError = ociissuer.ErrRetryable
	count, err = (GarbageCollector{Client: fake}).RunOnce(context.Background())
	require.ErrorIs(t, err, ociissuer.ErrRetryable)
	require.Zero(t, count)

	count, err = (GarbageCollector{Client: listErrorClient{FakeClient: ociissuer.NewFakeClient()}}).RunOnce(context.Background())
	require.ErrorIs(t, err, ociissuer.ErrRetryable)
	require.Zero(t, count)
}

func requestObject(csrPEM []byte) signer.CertificateRequestObject {
	cr := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "request",
			Namespace: "default",
			UID:       types.UID("request-uid"),
		},
		Spec: cmapi.CertificateRequestSpec{
			Request:  csrPEM,
			Duration: &metav1.Duration{Duration: 24 * time.Hour},
			IssuerRef: cmmeta.ObjectReference{
				Group: casv1alpha1.GroupName,
				Kind:  "OCIIssuer",
				Name:  "issuer",
			},
		},
	}
	return signer.CertificateRequestObjectFromCertificateRequest(cr)
}

func issuerObject() *casv1alpha1.OCIIssuer {
	return &casv1alpha1.OCIIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "issuer", Namespace: "default"},
		Spec: casv1alpha1.IssuerSpec{
			CertificateAuthorityID: "ocid1.certificateauthority.oc1.test",
			CompartmentID:          "ocid1.compartment.oc1.test",
			Region:                 "us-ashburn-1",
		},
	}
}

func ownedResource(id string, state ociissuer.LifecycleState) ociissuer.CertificateResource {
	return ociissuer.CertificateResource{
		ID:             id,
		Name:           "oci-cas-request-uid",
		LifecycleState: state,
		Tags: map[string]string{
			tagManaged:          tagManagedValue,
			tagRequestUID:       "request-uid",
			tagRequestNamespace: "default",
			tagRequestName:      "request",
		},
	}
}

func testCA(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

func testCSR(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "example.com"},
		DNSNames: []string{"example.com"},
	}, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}

func signCSR(t *testing.T, csrPEM []byte, ca *x509.Certificate, caKey crypto.Signer) []byte {
	return signCSRWithMutation(t, csrPEM, ca, caKey, func(*x509.Certificate) {})
}

func signCSRWithMutation(t *testing.T, csrPEM []byte, ca *x509.Certificate, caKey crypto.Signer, mutate func(*x509.Certificate)) []byte {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	require.NotNil(t, block)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	mutate(tmpl)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, csr.PublicKey, caKey)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
