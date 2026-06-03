package controller

import (
	"context"
	"time"

	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	issuercontrollers "github.com/cert-manager/issuer-lib/controllers"
	ctrl "sigs.k8s.io/controller-runtime"

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
	i.client = mgr.GetClient()
	if i.ClientFactory == nil {
		i.ClientFactory = RealClientFactory{ConfigProviders: ociissuer.ConfigProviderFactory{
			Client:                   mgr.GetClient(),
			ClusterResourceNamespace: i.ClusterResourceNamespace,
		}}
	}
	return (&issuercontrollers.CombinedController{
		IssuerTypes:        []issuerapi.Issuer{&casv1alpha1.OCIIssuer{}},
		ClusterIssuerTypes: []issuerapi.Issuer{&casv1alpha1.OCIClusterIssuer{}},
		FieldOwner:         FieldOwner,
		MaxRetryDuration:   10 * time.Minute,
		Sign:               i.Sign,
		Check:              i.Check,
		EventRecorder:      mgr.GetEventRecorderFor(FieldOwner),
	}).SetupWithManager(ctx, mgr)
}
