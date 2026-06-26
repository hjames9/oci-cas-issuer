package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/oci-cert-manager/oci-cas-issuer/internal/controller"
)

func TestParseOptions(t *testing.T) {
	opts, err := parseOptions(nil)
	require.NoError(t, err)
	require.Equal(t, ":8080", opts.metricsAddr)
	require.Equal(t, ":8081", opts.probeAddr)
	require.False(t, opts.leaderElect)
	require.Empty(t, opts.clusterResourceNamespace)
	require.Equal(t, controller.DefaultDeleteWait, opts.ociCertificateDeleteAfter)
	require.Equal(t, controller.DefaultGarbageCollectorInterval, opts.garbageCollectorInterval)

	opts, err = parseOptions([]string{
		"--metrics-bind-address=:9090",
		"--health-probe-bind-address=:9091",
		"--leader-elect",
		"--cluster-resource-namespace=cluster-secrets",
		"--oci-certificate-delete-after=24h",
		"--garbage-collector-interval=30m",
	})
	require.NoError(t, err)
	require.Equal(t, ":9090", opts.metricsAddr)
	require.Equal(t, ":9091", opts.probeAddr)
	require.True(t, opts.leaderElect)
	require.Equal(t, "cluster-secrets", opts.clusterResourceNamespace)
	require.Equal(t, 24*time.Hour, opts.ociCertificateDeleteAfter)
	require.Equal(t, 30*time.Minute, opts.garbageCollectorInterval)

	_, err = parseOptions([]string{"--does-not-exist"})
	require.Error(t, err)
}

func TestRunUsesOptionsAndStartsManager(t *testing.T) {
	ctx := context.Background()
	manager := &fakeControllerManager{}
	runtime := runtimeDependencies{
		namespace: func() (string, error) {
			t.Fatal("namespace should not be read when option is set")
			return "", nil
		},
		context: func() context.Context { return ctx },
		newManager: func(options ctrl.Options) (controllerManager, error) {
			require.Equal(t, ":9090", options.Metrics.BindAddress)
			require.Equal(t, ":9091", options.HealthProbeBindAddress)
			require.True(t, options.LeaderElection)
			require.Equal(t, "oci-cas-issuer.cert-manager.io", options.LeaderElectionID)
			require.Equal(t, scheme, options.Scheme)
			return manager, nil
		},
		setupIssuer: func(gotCtx context.Context, gotManager controllerManager, issuer controller.Issuer) error {
			require.Equal(t, ctx, gotCtx)
			require.Equal(t, manager, gotManager)
			require.Equal(t, "cluster-secrets", issuer.ClusterResourceNamespace)
			require.Equal(t, controller.CleanupPolicy{DeleteAfter: 24 * time.Hour}, issuer.CleanupPolicy)
			require.Equal(t, 30*time.Minute, issuer.GarbageCollectorInterval)
			return nil
		},
	}

	err := run(options{
		metricsAddr:               ":9090",
		probeAddr:                 ":9091",
		leaderElect:               true,
		clusterResourceNamespace:  "cluster-secrets",
		ociCertificateDeleteAfter: 24 * time.Hour,
		garbageCollectorInterval:  30 * time.Minute,
	}, runtime)
	require.NoError(t, err)
	require.Equal(t, []string{"healthz"}, manager.healthChecks)
	require.Equal(t, []string{"readyz"}, manager.readyChecks)
	require.True(t, manager.started)
	require.Equal(t, ctx, manager.startContext)
}

func TestRunUsesInClusterNamespace(t *testing.T) {
	manager := &fakeControllerManager{}
	err := run(defaultOptions(), runtimeDependencies{
		namespace: func() (string, error) { return "pod-namespace", nil },
		context:   context.Background,
		newManager: func(ctrl.Options) (controllerManager, error) {
			return manager, nil
		},
		setupIssuer: func(_ context.Context, _ controllerManager, issuer controller.Issuer) error {
			require.Equal(t, "pod-namespace", issuer.ClusterResourceNamespace)
			return nil
		},
	})
	require.NoError(t, err)
}

func TestRunErrors(t *testing.T) {
	tests := []struct {
		name      string
		runtime   func(error) runtimeDependencies
		assertErr string
	}{
		{
			name: "namespace",
			runtime: func(err error) runtimeDependencies {
				return runtimeDependencies{
					namespace: func() (string, error) { return "", err },
				}
			},
			assertErr: "determine cluster resource namespace",
		},
		{
			name: "new manager",
			runtime: func(err error) runtimeDependencies {
				return runtimeDependencies{
					namespace: func() (string, error) { return "namespace", nil },
					newManager: func(ctrl.Options) (controllerManager, error) {
						return nil, err
					},
				}
			},
			assertErr: "start manager",
		},
		{
			name: "setup issuer",
			runtime: func(err error) runtimeDependencies {
				return successfulRuntimeWithManager(&fakeControllerManager{}, func(context.Context, controllerManager, controller.Issuer) error {
					return err
				})
			},
			assertErr: "setup issuer controller",
		},
		{
			name: "health",
			runtime: func(err error) runtimeDependencies {
				return successfulRuntimeWithManager(&fakeControllerManager{healthErr: err}, nil)
			},
			assertErr: "add health check",
		},
		{
			name: "ready",
			runtime: func(err error) runtimeDependencies {
				return successfulRuntimeWithManager(&fakeControllerManager{readyErr: err}, nil)
			},
			assertErr: "add ready check",
		},
		{
			name: "start",
			runtime: func(err error) runtimeDependencies {
				return successfulRuntimeWithManager(&fakeControllerManager{startErr: err}, nil)
			},
			assertErr: "run manager",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cause := errors.New("boom")
			err := run(defaultOptions(), tt.runtime(cause))
			require.ErrorIs(t, err, cause)
			require.ErrorContains(t, err, tt.assertErr)
		})
	}
}

func TestDefaultRuntime(t *testing.T) {
	originalGetConfig := getConfigOrDie
	originalNewManager := newCtrlManager
	t.Cleanup(func() {
		getConfigOrDie = originalGetConfig
		newCtrlManager = originalNewManager
	})

	config := &rest.Config{Host: "https://unit.test"}
	manager := &fakeControllerManager{}
	getConfigOrDie = func() *rest.Config { return config }
	newCtrlManager = func(gotConfig *rest.Config, gotOptions ctrl.Options) (controllerManager, error) {
		require.Same(t, config, gotConfig)
		require.Equal(t, ":8080", gotOptions.Metrics.BindAddress)
		return manager, nil
	}

	runtime := defaultRuntime()
	require.NotNil(t, runtime.namespace)
	require.NotNil(t, runtime.context)
	require.NotNil(t, runtime.newManager)
	require.NotNil(t, runtime.setupIssuer)

	gotManager, err := runtime.newManager(ctrl.Options{
		Metrics: metricsserver.Options{BindAddress: ":8080"},
	})
	require.NoError(t, err)
	require.Same(t, manager, gotManager)

	require.Panics(t, func() {
		_ = runtime.setupIssuer(context.Background(), &fakeControllerManager{}, controller.Issuer{})
	})
}

func TestInClusterNamespaceOutsideCluster(t *testing.T) {
	namespace, err := inClusterNamespace()
	if err == nil {
		require.NotEmpty(t, namespace)
		return
	}
	require.True(t, errors.Is(err, errNotInCluster) || namespace == "")
}

func TestNamespaceFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "namespace")
	require.NoError(t, os.WriteFile(path, []byte("oci-cas-issuer"), 0600))

	namespace, err := namespaceFromFile(path)
	require.NoError(t, err)
	require.Equal(t, "oci-cas-issuer", namespace)

	namespace, err = namespaceFromFile(filepath.Join(t.TempDir(), "missing"))
	require.ErrorIs(t, err, errNotInCluster)
	require.Empty(t, namespace)

	namespace, err = namespaceFromFile(t.TempDir())
	require.ErrorContains(t, err, "read namespace")
	require.Empty(t, namespace)
}

func successfulRuntimeWithManager(manager *fakeControllerManager, setup func(context.Context, controllerManager, controller.Issuer) error) runtimeDependencies {
	if setup == nil {
		setup = func(context.Context, controllerManager, controller.Issuer) error { return nil }
	}
	return runtimeDependencies{
		namespace: func() (string, error) { return "namespace", nil },
		context:   context.Background,
		newManager: func(ctrl.Options) (controllerManager, error) {
			return manager, nil
		},
		setupIssuer: setup,
	}
}

type fakeControllerManager struct {
	healthErr    error
	readyErr     error
	startErr     error
	healthChecks []string
	readyChecks  []string
	started      bool
	startContext context.Context
}

func (m *fakeControllerManager) AddHealthzCheck(name string, check healthz.Checker) error {
	if m.healthErr != nil {
		return m.healthErr
	}
	m.healthChecks = append(m.healthChecks, name)
	return nil
}

func (m *fakeControllerManager) AddReadyzCheck(name string, check healthz.Checker) error {
	if m.readyErr != nil {
		return m.readyErr
	}
	m.readyChecks = append(m.readyChecks, name)
	return nil
}

func (m *fakeControllerManager) Start(ctx context.Context) error {
	if m.startErr != nil {
		return m.startErr
	}
	m.started = true
	m.startContext = ctx
	return nil
}
