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

	issuercontrollers "github.com/cert-manager/issuer-lib/controllers"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
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

func TestSetupWithManagerWrapper(t *testing.T) {
	original := setupCombinedController
	t.Cleanup(func() { setupCombinedController = original })

	ctx := context.Background()
	kubeClient := fake.NewClientBuilder().Build()
	mgr := &setupWithManagerTestManager{
		setupTestManager: setupTestManager{client: kubeClient, recorder: record.NewFakeRecorder(1)},
	}

	setupCombinedController = func(gotCtx context.Context, combined *issuercontrollers.CombinedController, gotManager ctrl.Manager) error {
		require.Equal(t, ctx, gotCtx)
		require.Same(t, mgr, gotManager)
		require.Equal(t, FieldOwner, combined.FieldOwner)
		require.True(t, combined.SetCAOnCertificateRequest)
		return nil
	}

	err := (Issuer{ClientFactory: staticFactory{}}).SetupWithManager(ctx, mgr)
	require.NoError(t, err)
	require.Len(t, mgr.added, 1)

	setupErr := errors.New("setup")
	setupCombinedController = func(context.Context, *issuercontrollers.CombinedController, ctrl.Manager) error {
		return setupErr
	}
	err = (Issuer{ClientFactory: staticFactory{}}).SetupWithManager(ctx, mgr)
	require.ErrorIs(t, err, setupErr)
}

func TestSetupWithManagerWrapperReturnsPrepareError(t *testing.T) {
	original := setupCombinedController
	t.Cleanup(func() { setupCombinedController = original })
	setupCombinedController = func(context.Context, *issuercontrollers.CombinedController, ctrl.Manager) error {
		t.Fatal("combined controller setup should not run")
		return nil
	}

	addErr := errors.New("add")
	err := (Issuer{ClientFactory: staticFactory{}}).SetupWithManager(context.Background(), &setupWithManagerTestManager{
		setupTestManager: setupTestManager{
			client:   fake.NewClientBuilder().Build(),
			addErr:   addErr,
			recorder: record.NewFakeRecorder(1),
		},
	})
	require.ErrorIs(t, err, addErr)
}

func TestDefaultSetupCombinedController(t *testing.T) {
	original := combinedControllerSetupWithManager
	t.Cleanup(func() { combinedControllerSetupWithManager = original })

	ctx := context.Background()
	combined := &issuercontrollers.CombinedController{FieldOwner: FieldOwner}
	mgr := &setupWithManagerTestManager{
		setupTestManager: setupTestManager{
			client:   fake.NewClientBuilder().Build(),
			recorder: record.NewFakeRecorder(1),
		},
	}
	combinedControllerSetupWithManager = func(gotCtx context.Context, gotCombined *issuercontrollers.CombinedController, gotManager ctrl.Manager) error {
		require.Equal(t, ctx, gotCtx)
		require.Same(t, combined, gotCombined)
		require.Same(t, mgr, gotManager)
		return errors.New("setup")
	}

	err := setupCombinedController(ctx, combined, mgr)
	require.ErrorContains(t, err, "setup")
}

func TestDefaultCombinedControllerSetupWithManager(t *testing.T) {
	require.Panics(t, func() {
		_ = combinedControllerSetupWithManager(context.Background(), &issuercontrollers.CombinedController{}, &setupWithManagerTestManager{})
	})
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

type setupWithManagerTestManager struct {
	ctrl.Manager
	setupTestManager
}

func (m *setupWithManagerTestManager) GetClient() client.Client {
	return m.setupTestManager.GetClient()
}

func (m *setupWithManagerTestManager) Add(runnable ctrlmanager.Runnable) error {
	return m.setupTestManager.Add(runnable)
}

func (m *setupWithManagerTestManager) GetEventRecorderFor(name string) record.EventRecorder {
	return m.setupTestManager.GetEventRecorderFor(name)
}
