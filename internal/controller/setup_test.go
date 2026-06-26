package controller

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	ctrlmanager "sigs.k8s.io/controller-runtime/pkg/manager"

	casv1alpha1 "github.com/oci-cert-manager/oci-cas-issuer/api/v1alpha1"
	ociissuer "github.com/oci-cert-manager/oci-cas-issuer/internal/oci"
)

func TestCombinedControllerOptions(t *testing.T) {
	recorder := record.NewFakeRecorder(1)
	controller := Issuer{}.combinedController(recorder)

	require.Equal(t, FieldOwner, controller.FieldOwner)
	require.Equal(t, 10*time.Minute, controller.MaxRetryDuration)
	require.True(t, controller.SetCAOnCertificateRequest)
	require.Same(t, recorder, controller.EventRecorder)
	require.Len(t, controller.IssuerTypes, 1)
	require.IsType(t, &casv1alpha1.OCIIssuer{}, controller.IssuerTypes[0])
	require.Len(t, controller.ClusterIssuerTypes, 1)
	require.IsType(t, &casv1alpha1.OCIClusterIssuer{}, controller.ClusterIssuerTypes[0])
	require.NotNil(t, controller.Sign)
	require.NotNil(t, controller.Check)
}

func TestPrepareManagerDefaultsAndAddsGarbageCollector(t *testing.T) {
	kubeClient := fake.NewClientBuilder().Build()
	mgr := &setupTestManager{client: kubeClient, recorder: record.NewFakeRecorder(1)}

	configured, err := (Issuer{
		ClusterResourceNamespace: "cluster-resources",
		GarbageCollectorInterval: -1,
	}).prepareManager(mgr)
	require.NoError(t, err)
	require.Same(t, kubeClient, configured.client)
	require.IsType(t, RealClientFactory{}, configured.ClientFactory)
	require.Zero(t, configured.GarbageCollectorInterval)
	require.Len(t, mgr.added, 1)

	runner, ok := mgr.added[0].(GarbageCollectorRunner)
	require.True(t, ok)
	require.Same(t, kubeClient, runner.Client)
	require.Equal(t, "cluster-resources", runner.ClusterResourceNamespace)
	require.Zero(t, runner.Interval)
}

func TestPrepareManagerReturnsAddError(t *testing.T) {
	addErr := errors.New("add")
	_, err := (Issuer{ClientFactory: staticFactory{}}).prepareManager(&setupTestManager{
		client:   fake.NewClientBuilder().Build(),
		addErr:   addErr,
		recorder: record.NewFakeRecorder(1),
	})
	require.ErrorIs(t, err, addErr)
}

func TestRealClientFactoryReturnsConfigProviderError(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	factory := RealClientFactory{ConfigProviders: ociissuer.ConfigProviderFactory{
		Client: fake.NewClientBuilder().WithScheme(scheme).Build(),
	}}
	_, err := factory.ForIssuer(context.Background(), "default", casv1alpha1.IssuerSpec{
		Region: "us-ashburn-1",
		Auth: casv1alpha1.OCIAuth{
			Type:            casv1alpha1.AuthTypeAPIKey,
			APIKeySecretRef: &casv1alpha1.SecretKeySelector{Name: "missing"},
		},
	})
	require.ErrorContains(t, err, "get api key secret")
}

func TestRealClientFactoryBuildsClient(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privateKey := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
	factory := RealClientFactory{ConfigProviders: ociissuer.ConfigProviderFactory{
		WorkloadIdentityProvider: func(string) (common.ConfigurationProvider, error) {
			return common.NewRawConfigurationProvider("tenancy", "user", "us-ashburn-1", "fingerprint", privateKey, nil), nil
		},
	}}

	client, err := factory.ForIssuer(context.Background(), "default", casv1alpha1.IssuerSpec{Region: "us-ashburn-1"})
	require.NoError(t, err)
	require.NotNil(t, client)
}

type setupTestManager struct {
	client   client.Client
	addErr   error
	added    []ctrlmanager.Runnable
	recorder record.EventRecorder
}

func (m *setupTestManager) GetClient() client.Client {
	return m.client
}

func (m *setupTestManager) Add(runnable ctrlmanager.Runnable) error {
	if m.addErr != nil {
		return m.addErr
	}
	m.added = append(m.added, runnable)
	return nil
}

func (m *setupTestManager) GetEventRecorderFor(string) record.EventRecorder {
	return m.recorder
}
