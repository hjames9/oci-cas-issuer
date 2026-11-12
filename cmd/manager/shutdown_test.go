package main

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	casv1alpha1 "github.com/oci-cert-manager/oci-cas-issuer/api/v1alpha1"
	"github.com/oci-cert-manager/oci-cas-issuer/internal/controller"
	ociissuer "github.com/oci-cert-manager/oci-cas-issuer/internal/oci"
)

func TestManagerStopsOCIWorkBeforeReleasingLease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	stopped := make(chan struct{})
	lock := &shutdownLease{workStopped: stopped}
	ociClient := &shutdownOCIClient{Client: ociissuer.NewFakeClient(), started: make(chan struct{})}
	issuer := &casv1alpha1.OCIIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "issuer", Namespace: "default"},
		Spec: casv1alpha1.IssuerSpec{
			CertificateAuthorityID: "ocid1.certificateauthority.oc1.test",
			CompartmentID:          "ocid1.compartment.oc1.test",
			Region:                 "us-ashburn-1",
		},
	}
	opts := defaultOptions()
	opts.leaderElect = true
	opts.metricsAddr, opts.probeAddr = "0", "0"
	opts.clusterResourceNamespace = "default"
	done := make(chan error, 1)
	go func() {
		done <- run(opts, runtimeDependencies{
			context: func() context.Context { return ctx },
			newManager: func(options ctrl.Options) (controllerManager, error) {
				// Use real controller-runtime shutdown and leader-election logic with an in-memory lease.
				options.LeaderElectionResourceLockInterface = lock
				return ctrl.NewManager(&rest.Config{Host: "https://unit.test"}, options)
			},
			setupIssuer: func(_ context.Context, mgr controllerManager, _ controller.Issuer) error {
				return mgr.(ctrl.Manager).Add(observedCollector{
					GarbageCollectorRunner: controller.GarbageCollectorRunner{
						Client:        fake.NewClientBuilder().WithScheme(scheme).WithObjects(issuer).Build(),
						ClientFactory: shutdownFactory{client: ociClient},
						Interval:      time.Hour,
					},
					stopped: stopped,
				})
			},
		})
	}()
	select {
	case <-ociClient.started:
	case err := <-done:
		t.Fatalf("manager exited before starting OCI work: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("manager did not acquire leadership and start OCI work")
	}
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("manager did not stop after cancellation")
	}
	select {
	case <-stopped:
	default:
		t.Fatal("garbage collector still running after manager returned")
	}
	lock.mu.Lock()
	defer lock.mu.Unlock()
	require.True(t, lock.released)
	require.False(t, lock.releasedBeforeWorkStopped)
	require.Empty(t, lock.record.HolderIdentity)
	require.Equal(t, int64(1), ociClient.calls.Load())
}

type observedCollector struct {
	controller.GarbageCollectorRunner
	stopped chan struct{}
}

func (r observedCollector) Start(ctx context.Context) error {
	defer close(r.stopped)
	return r.GarbageCollectorRunner.Start(ctx)
}

type shutdownFactory struct{ client ociissuer.Client }

func (f shutdownFactory) ForIssuer(context.Context, string, casv1alpha1.IssuerSpec) (ociissuer.Client, error) {
	return f.client, nil
}

type shutdownOCIClient struct {
	ociissuer.Client
	started chan struct{}
	calls   atomic.Int64
}

func (c *shutdownOCIClient) ListManagedCertificates(ctx context.Context, _ string) ([]ociissuer.CertificateResource, error) {
	c.calls.Add(1)
	close(c.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

type shutdownLease struct {
	mu                        sync.Mutex
	record                    resourcelock.LeaderElectionRecord
	workStopped               <-chan struct{}
	released                  bool
	releasedBeforeWorkStopped bool
}

func (l *shutdownLease) Get(context.Context) (*resourcelock.LeaderElectionRecord, []byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	record := l.record
	raw, err := json.Marshal(record)
	return &record, raw, err
}

func (l *shutdownLease) Create(ctx context.Context, record resourcelock.LeaderElectionRecord) error {
	return l.Update(ctx, record)
}

func (l *shutdownLease) Update(_ context.Context, record resourcelock.LeaderElectionRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.record = record
	if record.HolderIdentity == "" {
		l.released = true
		select {
		case <-l.workStopped:
		default:
			l.releasedBeforeWorkStopped = true
		}
	}
	return nil
}

func (*shutdownLease) Identity() string   { return "test-manager" }
func (*shutdownLease) Describe() string   { return "in-memory shutdown test lease" }
func (*shutdownLease) RecordEvent(string) {}
