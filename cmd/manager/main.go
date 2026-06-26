package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	casv1alpha1 "github.com/oci-cert-manager/oci-cas-issuer/api/v1alpha1"
	"github.com/oci-cert-manager/oci-cas-issuer/internal/controller"
)

const inClusterNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

var (
	scheme         = runtime.NewScheme()
	setupLog       = ctrl.Log.WithName("setup")
	getConfigOrDie = ctrl.GetConfigOrDie
	newCtrlManager = func(config *rest.Config, options ctrl.Options) (controllerManager, error) {
		return ctrl.NewManager(config, options)
	}
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(cmapi.AddToScheme(scheme))
	utilruntime.Must(casv1alpha1.AddToScheme(scheme))
}

func main() {
	if err := runMain(os.Args[1:], defaultRuntime()); err != nil {
		setupLog.Error(err, "manager exited")
		os.Exit(1)
	}
}

func runMain(args []string, runtime runtimeDependencies) error {
	options, err := parseOptions(args)
	if err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&options.zapOptions)))
	return run(options, runtime)
}

type options struct {
	metricsAddr               string
	probeAddr                 string
	leaderElect               bool
	clusterResourceNamespace  string
	ociCertificateDeleteAfter time.Duration
	garbageCollectorInterval  time.Duration
	zapOptions                zap.Options
}

func defaultOptions() options {
	return options{
		metricsAddr:               ":8080",
		probeAddr:                 ":8081",
		ociCertificateDeleteAfter: controller.DefaultDeleteWait,
		garbageCollectorInterval:  controller.DefaultGarbageCollectorInterval,
	}
}

func parseOptions(args []string) (options, error) {
	parsed := defaultOptions()
	flags := flag.NewFlagSet("oci-cas-issuer", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	bindFlags(flags, &parsed)
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	return parsed, nil
}

func bindFlags(flags *flag.FlagSet, opts *options) {
	flags.StringVar(&opts.metricsAddr, "metrics-bind-address", opts.metricsAddr, "The address the metrics endpoint binds to.")
	flags.StringVar(&opts.probeAddr, "health-probe-bind-address", opts.probeAddr, "The address the probe endpoint binds to.")
	flags.BoolVar(&opts.leaderElect, "leader-elect", opts.leaderElect, "Enable leader election.")
	flags.StringVar(&opts.clusterResourceNamespace, "cluster-resource-namespace", opts.clusterResourceNamespace, "Namespace for cluster-scoped issuer referenced Secrets.")
	flags.DurationVar(&opts.ociCertificateDeleteAfter, "oci-certificate-delete-after", opts.ociCertificateDeleteAfter, "Delay before OCI Certificate resources created by this controller are deleted.")
	flags.DurationVar(&opts.garbageCollectorInterval, "garbage-collector-interval", opts.garbageCollectorInterval, "Interval for scanning issuer compartments and scheduling deletion of tagged OCI Certificate resources. Set to 0 to disable.")
	opts.zapOptions.BindFlags(flags)
}

type controllerManager interface {
	AddHealthzCheck(name string, check healthz.Checker) error
	AddReadyzCheck(name string, check healthz.Checker) error
	Start(ctx context.Context) error
}

type runtimeDependencies struct {
	namespace   func() (string, error)
	context     func() context.Context
	newManager  func(ctrl.Options) (controllerManager, error)
	setupIssuer func(context.Context, controllerManager, controller.Issuer) error
}

func defaultRuntime() runtimeDependencies {
	return runtimeDependencies{
		namespace: inClusterNamespace,
		context:   ctrl.SetupSignalHandler,
		newManager: func(options ctrl.Options) (controllerManager, error) {
			return newCtrlManager(getConfigOrDie(), options)
		},
		setupIssuer: func(ctx context.Context, mgr controllerManager, issuer controller.Issuer) error {
			return issuer.SetupWithManager(ctx, mgr.(ctrl.Manager))
		},
	}
}

func run(opts options, runtime runtimeDependencies) error {
	clusterResourceNamespace := opts.clusterResourceNamespace
	if clusterResourceNamespace == "" {
		ns, err := runtime.namespace()
		if err != nil {
			return fmt.Errorf("determine cluster resource namespace: %w", err)
		}
		clusterResourceNamespace = ns
	}

	mgr, err := runtime.newManager(ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: opts.metricsAddr},
		HealthProbeBindAddress: opts.probeAddr,
		LeaderElection:         opts.leaderElect,
		LeaderElectionID:       "oci-cas-issuer.cert-manager.io",
	})
	if err != nil {
		return fmt.Errorf("start manager: %w", err)
	}

	ctx := runtime.context()
	if err := runtime.setupIssuer(ctx, mgr, controller.Issuer{
		ClusterResourceNamespace: clusterResourceNamespace,
		CleanupPolicy:            controller.CleanupPolicy{DeleteAfter: opts.ociCertificateDeleteAfter},
		GarbageCollectorInterval: opts.garbageCollectorInterval,
	}); err != nil {
		return fmt.Errorf("setup issuer controller: %w", err)
	}
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("add health check: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("add ready check: %w", err)
	}
	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("run manager: %w", err)
	}
	return nil
}

var errNotInCluster = errors.New("not running in-cluster")

func inClusterNamespace() (string, error) {
	return namespaceFromFile(inClusterNamespacePath)
}

func namespaceFromFile(path string) (string, error) {
	namespace, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", errNotInCluster
	}
	if err != nil {
		return "", fmt.Errorf("read namespace: %w", err)
	}
	return string(namespace), nil
}
