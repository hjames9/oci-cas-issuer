package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	casv1alpha1 "github.com/oci-cert-manager/oci-cas-issuer/api/v1alpha1"
	ociissuer "github.com/oci-cert-manager/oci-cas-issuer/internal/oci"
)

const DefaultGarbageCollectorInterval = time.Hour

type GarbageCollectorRunner struct {
	Client                   client.Client
	ClientFactory            ClientFactory
	ClusterResourceNamespace string
	CleanupPolicy            CleanupPolicy
	Interval                 time.Duration
}

func (r GarbageCollectorRunner) NeedLeaderElection() bool {
	return true
}

func (r GarbageCollectorRunner) Start(ctx context.Context) error {
	if r.Interval <= 0 {
		return nil
	}
	err := wait.PollUntilContextCancel(ctx, r.Interval, true, func(ctx context.Context) (bool, error) {
		if err := r.RunOnce(ctx); err != nil {
			ctrl.LoggerFrom(ctx).Error(err, "OCI garbage collection failed")
		}
		return false, nil
	})
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func (r GarbageCollectorRunner) RunOnce(ctx context.Context) error {
	if r.Client == nil || r.ClientFactory == nil {
		return nil
	}

	var errs []error
	seen := map[string]struct{}{}
	log := ctrl.LoggerFrom(ctx)

	var issuers casv1alpha1.OCIIssuerList
	if err := r.Client.List(ctx, &issuers); err != nil {
		errs = append(errs, fmt.Errorf("list OCIIssuers: %w", err))
	} else {
		for i := range issuers.Items {
			issuer := &issuers.Items[i]
			errs = append(errs, r.runForIssuer(ctx, issuer.Namespace, issuer.Spec, seen)...)
		}
	}

	var clusterIssuers casv1alpha1.OCIClusterIssuerList
	if err := r.Client.List(ctx, &clusterIssuers); err != nil {
		errs = append(errs, fmt.Errorf("list OCIClusterIssuers: %w", err))
	} else {
		for i := range clusterIssuers.Items {
			issuer := &clusterIssuers.Items[i]
			errs = append(errs, r.runForIssuer(ctx, r.ClusterResourceNamespace, issuer.Spec, seen)...)
		}
	}

	for _, err := range errs {
		log.Error(err, "OCI garbage collection issuer scan failed")
	}
	if len(errs) > 0 {
		return fmt.Errorf("OCI garbage collection had %d issuer scan errors", len(errs))
	}
	return nil
}

func (r GarbageCollectorRunner) runForIssuer(ctx context.Context, namespace string, spec casv1alpha1.IssuerSpec, seen map[string]struct{}) []error {
	if err := validateIssuerSpec(spec); err != nil {
		return []error{fmt.Errorf("validate issuer spec: %w", err)}
	}
	if r.ClientFactory == nil {
		return []error{fmt.Errorf("build OCI client: missing client factory")}
	}
	ociClient, err := r.ClientFactory.ForIssuer(ctx, namespace, spec)
	if err != nil {
		return []error{fmt.Errorf("build OCI client: %w", err)}
	}
	certs, err := ociClient.ListManagedCertificates(ctx, spec.CompartmentID)
	if err != nil {
		return []error{fmt.Errorf("list OCI managed certificates: %w", err)}
	}

	var errs []error
	policy := cleanupPolicy(r.CleanupPolicy)
	for _, cert := range certs {
		if cert.Tags[tagManaged] != tagManagedValue {
			continue
		}
		if cert.LifecycleState != "" && cert.LifecycleState != ociissuer.LifecycleActive {
			continue
		}
		if _, ok := seen[cert.ID]; ok {
			continue
		}
		seen[cert.ID] = struct{}{}
		if err := scheduleDeletion(ctx, ociClient, policy, cert.ID, time.Now); err != nil {
			errs = append(errs, fmt.Errorf("schedule deletion for OCI certificate %s: %w", cert.ID, err))
		}
	}
	return errs
}
