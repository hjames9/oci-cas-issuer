package controller

import (
	"context"
	"time"

	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	issuercontrollers "github.com/cert-manager/issuer-lib/controllers"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlmanager "sigs.k8s.io/controller-runtime/pkg/manager"

	casv1alpha1 "github.com/oci-cert-manager/oci-cas-issuer/api/v1alpha1"
	ociissuer "github.com/oci-cert-manager/oci-cas-issuer/internal/oci"
)

type RealClientFactory struct {
	ConfigProviders ociissuer.ConfigProviderFactory
}

func (f RealClientFactory) ForIssuer(ctx context.Context, namespace string, spec casv1alpha1.IssuerSpec) (ociissuer.Client, error) {
	provider, err := f.ConfigProviders.Provider(ctx, namespace, spec)
	if err != nil {
		return nil, err
	}
	return ociissuer.NewRealClient(provider, spec.Region)
}

func (i Issuer) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	configured, err := i.prepareManager(mgr)
	if err != nil {
		return err
	}
	return setupCombinedController(ctx, configured.combinedController(mgr.GetEventRecorderFor(FieldOwner)), mgr)
}

var setupCombinedController = func(ctx context.Context, combined *issuercontrollers.CombinedController, mgr ctrl.Manager) error {
	return combined.SetupWithManager(ctx, mgr)
}

type setupManager interface {
	GetClient() client.Client
	Add(ctrlmanager.Runnable) error
	GetEventRecorderFor(name string) record.EventRecorder
}

func (i Issuer) prepareManager(mgr setupManager) (Issuer, error) {
	i.client = mgr.GetClient()
	if i.ClientFactory == nil {
		i.ClientFactory = RealClientFactory{ConfigProviders: ociissuer.ConfigProviderFactory{
			Client:                   mgr.GetClient(),
			ClusterResourceNamespace: i.ClusterResourceNamespace,
		}}
	}
	if i.GarbageCollectorInterval < 0 {
		i.GarbageCollectorInterval = 0
	}
	if err := mgr.Add(GarbageCollectorRunner{
		Client:                   mgr.GetClient(),
		ClientFactory:            i.ClientFactory,
		ClusterResourceNamespace: i.ClusterResourceNamespace,
		CleanupPolicy:            cleanupPolicy(i.CleanupPolicy),
		Interval:                 i.GarbageCollectorInterval,
	}); err != nil {
		return Issuer{}, err
	}
	return i, nil
}

func (i Issuer) combinedController(eventRecorder record.EventRecorder) *issuercontrollers.CombinedController {
	return &issuercontrollers.CombinedController{
		IssuerTypes:               []issuerapi.Issuer{&casv1alpha1.OCIIssuer{}},
		ClusterIssuerTypes:        []issuerapi.Issuer{&casv1alpha1.OCIClusterIssuer{}},
		FieldOwner:                FieldOwner,
		MaxRetryDuration:          10 * time.Minute,
		Sign:                      i.Sign,
		Check:                     i.Check,
		EventRecorder:             eventRecorder,
		SetCAOnCertificateRequest: true,
	}
}
