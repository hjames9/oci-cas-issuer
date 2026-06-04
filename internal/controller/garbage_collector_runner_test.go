package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	casv1alpha1 "github.com/oci-cert-manager/oci-cas-issuer/api/v1alpha1"
	ociissuer "github.com/oci-cert-manager/oci-cas-issuer/internal/oci"
)

type cancelingFactory struct {
	client ociissuer.Client
	cancel context.CancelFunc
}

func (f cancelingFactory) ForIssuer(context.Context, string, casv1alpha1.IssuerSpec) (ociissuer.Client, error) {
	f.cancel()
	return f.client, nil
}

func TestGarbageCollectorRunnerStart(t *testing.T) {
	require.True(t, GarbageCollectorRunner{}.NeedLeaderElection())
	require.NoError(t, GarbageCollectorRunner{}.Start(context.Background()))

	ctx, cancel := context.WithCancel(context.Background())
	scheme := runnerScheme(t)
	ociClient := ociissuer.NewFakeClient()
	ociClient.Certificates["cert"] = ociissuer.CertificateResource{
		ID:             "cert",
		LifecycleState: ociissuer.LifecycleActive,
		Tags:           map[string]string{tagManaged: tagManagedValue},
	}
	runner := GarbageCollectorRunner{
		Client:        fake.NewClientBuilder().WithScheme(scheme).WithObjects(validRunnerIssuer()).Build(),
		ClientFactory: cancelingFactory{client: ociClient, cancel: cancel},
		Interval:      time.Hour,
	}
	require.NoError(t, runner.Start(ctx))
	require.Equal(t, []string{"cert"}, ociClient.Deleted)

	deadlineCtx, deadlineCancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer deadlineCancel()
	err := GarbageCollectorRunner{
		Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(&casv1alpha1.OCIIssuer{
			ObjectMeta: metav1.ObjectMeta{Name: "bad", Namespace: "default"},
			Spec:       casv1alpha1.IssuerSpec{CertificateAuthorityID: "bad"},
		}).Build(),
		ClientFactory: staticFactory{client: ociissuer.NewFakeClient()},
		Interval:      time.Hour,
	}.Start(deadlineCtx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestGarbageCollectorRunnerRunOnceSchedulesTaggedActiveCertificates(t *testing.T) {
	scheme := runnerScheme(t)
	ociClient := ociissuer.NewFakeClient()
	ociClient.Certificates["managed"] = ociissuer.CertificateResource{
		ID:             "managed",
		LifecycleState: ociissuer.LifecycleActive,
		Tags:           map[string]string{tagManaged: tagManagedValue},
	}
	ociClient.Certificates["unknown-state"] = ociissuer.CertificateResource{
		ID:   "unknown-state",
		Tags: map[string]string{tagManaged: tagManagedValue},
	}
	ociClient.Certificates["creating"] = ociissuer.CertificateResource{
		ID:             "creating",
		LifecycleState: ociissuer.LifecycleCreating,
		Tags:           map[string]string{tagManaged: tagManagedValue},
	}
	ociClient.Certificates["unmanaged"] = ociissuer.CertificateResource{
		ID:             "unmanaged",
		LifecycleState: ociissuer.LifecycleActive,
		Tags:           map[string]string{},
	}

	err := GarbageCollectorRunner{
		Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(
			validRunnerIssuer(),
			validRunnerClusterIssuer(),
		).Build(),
		ClientFactory:            staticFactory{client: ociClient},
		ClusterResourceNamespace: "cluster-secrets",
		Interval:                 time.Hour,
	}.RunOnce(context.Background())
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"managed", "unknown-state"}, ociClient.Deleted)
}

func TestGarbageCollectorRunnerRunOnceHandlesErrors(t *testing.T) {
	err := GarbageCollectorRunner{}.RunOnce(context.Background())
	require.NoError(t, err)

	err = GarbageCollectorRunner{
		Client:        fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build(),
		ClientFactory: staticFactory{client: ociissuer.NewFakeClient()},
	}.RunOnce(context.Background())
	require.ErrorContains(t, err, "issuer scan errors")

	scheme := runnerScheme(t)
	err = GarbageCollectorRunner{
		Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(&casv1alpha1.OCIIssuer{
			ObjectMeta: metav1.ObjectMeta{Name: "bad", Namespace: "default"},
			Spec: casv1alpha1.IssuerSpec{
				CertificateAuthorityID: "bad",
				CompartmentID:          "ocid1.compartment.oc1.test",
				Region:                 "us-ashburn-1",
			},
		}).Build(),
		ClientFactory: staticFactory{client: ociissuer.NewFakeClient()},
	}.RunOnce(context.Background())
	require.ErrorContains(t, err, "issuer scan errors")

	err = GarbageCollectorRunner{
		Client:        fake.NewClientBuilder().WithScheme(scheme).WithObjects(validRunnerIssuer()).Build(),
		ClientFactory: staticFactory{err: errors.New("factory")},
	}.RunOnce(context.Background())
	require.ErrorContains(t, err, "issuer scan errors")

	err = GarbageCollectorRunner{
		Client:        fake.NewClientBuilder().WithScheme(scheme).WithObjects(validRunnerIssuer()).Build(),
		ClientFactory: staticFactory{client: listErrorClient{FakeClient: ociissuer.NewFakeClient()}},
	}.RunOnce(context.Background())
	require.ErrorContains(t, err, "issuer scan errors")

	deletingClient := ociissuer.NewFakeClient()
	deletingClient.Certificates["managed"] = ociissuer.CertificateResource{
		ID:             "managed",
		LifecycleState: ociissuer.LifecycleActive,
		Tags:           map[string]string{tagManaged: tagManagedValue},
	}
	deletingClient.DeleteError = ociissuer.ErrRetryable
	err = GarbageCollectorRunner{
		Client:        fake.NewClientBuilder().WithScheme(scheme).WithObjects(validRunnerIssuer()).Build(),
		ClientFactory: staticFactory{client: deletingClient},
	}.RunOnce(context.Background())
	require.ErrorContains(t, err, "issuer scan errors")
}

func TestGarbageCollectorRunnerRunForIssuerNilFactory(t *testing.T) {
	errs := GarbageCollectorRunner{}.runForIssuer(context.Background(), "default", issuerObject().Spec, map[string]struct{}{})
	require.Error(t, errs[0])
}

func runnerScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, casv1alpha1.AddToScheme(scheme))
	return scheme
}

func validRunnerIssuer() *casv1alpha1.OCIIssuer {
	return &casv1alpha1.OCIIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "issuer", Namespace: "default"},
		Spec:       issuerObject().Spec,
	}
}

func validRunnerClusterIssuer() *casv1alpha1.OCIClusterIssuer {
	return &casv1alpha1.OCIClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-issuer"},
		Spec:       issuerObject().Spec,
	}
}
