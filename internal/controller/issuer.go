package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cert-manager/cert-manager/pkg/util/pki"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	casv1alpha1 "github.com/oci-cert-manager/oci-cas-issuer/api/v1alpha1"
	ociissuer "github.com/oci-cert-manager/oci-cas-issuer/internal/oci"
)

const (
	FieldOwner             = "oci-cas-issuer.cert-manager.io"
	DefaultDeleteWait      = 48 * time.Hour
	tagRequestUID          = "cm-certificate-request-uid"
	tagRequestNamespace    = "cm-certificate-request-namespace"
	tagRequestName         = "cm-certificate-request-name"
	tagManaged             = "oci-cas-issuer-managed"
	tagManagedValue        = "true"
	defaultPendingRequeue  = 10 * time.Second
	defaultCreatingRequeue = 5 * time.Second
)

type ClientFactory interface {
	ForIssuer(ctx context.Context, namespace string, spec casv1alpha1.IssuerSpec) (ociissuer.Client, error)
}

type Issuer struct {
	ClientFactory            ClientFactory
	ClusterResourceNamespace string
	CleanupPolicy            CleanupPolicy
	GarbageCollectorInterval time.Duration

	client client.Client
}

// +kubebuilder:rbac:groups=cas.oci-issuer.cert-manager.io,resources=ociissuers;ociclusterissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=cas.oci-issuer.cert-manager.io,resources=ociissuers/status;ociclusterissuers/status,verbs=patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=patch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/status,verbs=patch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=signers,verbs=sign,resourceNames=ociclusterissuers.cas.oci-issuer.cert-manager.io/*;ociissuers.cas.oci-issuer.cert-manager.io/*

func (i Issuer) issuerDetails(obj issuerapi.Issuer) (casv1alpha1.IssuerSpec, string, error) {
	switch issuer := obj.(type) {
	case *casv1alpha1.OCIIssuer:
		return issuer.Spec, issuer.Namespace, nil
	case *casv1alpha1.OCIClusterIssuer:
		return issuer.Spec, i.ClusterResourceNamespace, nil
	default:
		return casv1alpha1.IssuerSpec{}, "", signer.PermanentError{Err: fmt.Errorf("unexpected issuer type %T", obj)}
	}
}

func (i Issuer) Check(ctx context.Context, issuerObject issuerapi.Issuer) error {
	spec, namespace, err := i.issuerDetails(issuerObject)
	if err != nil {
		return err
	}
	if err := validateIssuerSpec(spec); err != nil {
		return signer.PermanentError{Err: err}
	}
	ociClient, err := i.ClientFactory.ForIssuer(ctx, namespace, spec)
	if err != nil {
		return signer.PermanentError{Err: err}
	}
	if err := ociClient.CheckCertificateAuthority(ctx, spec.CertificateAuthorityID); err != nil {
		if errors.Is(err, ociissuer.ErrNotFound) {
			return signer.PermanentError{Err: err}
		}
		return err
	}
	return nil
}

func (i Issuer) Sign(ctx context.Context, cr signer.CertificateRequestObject, issuerObject issuerapi.Issuer) (signer.PEMBundle, error) {
	spec, namespace, err := i.issuerDetails(issuerObject)
	if err != nil {
		return signer.PEMBundle{}, signer.IssuerError{Err: err}
	}
	if err := validateIssuerSpec(spec); err != nil {
		return signer.PEMBundle{}, signer.IssuerError{Err: err}
	}
	ociClient, err := i.ClientFactory.ForIssuer(ctx, namespace, spec)
	if err != nil {
		return signer.PEMBundle{}, signer.IssuerError{Err: err}
	}
	details, err := cr.GetCertificateDetails()
	if err != nil {
		return signer.PEMBundle{}, signer.PermanentError{Err: err}
	}
	validated, err := validateCertificateRequest(details)
	if err != nil {
		return signer.PEMBundle{}, signer.PermanentError{Err: err}
	}

	requestStart := time.Now().UTC()
	name := certificateName(cr.GetUID())
	tags := requestTags(cr)
	resource, err := ociClient.CreateCertificate(ctx, ociissuer.IssueRequest{
		CompartmentID:          spec.CompartmentID,
		CertificateAuthorityID: spec.CertificateAuthorityID,
		Name:                   name,
		CSRPem:                 string(details.CSR),
		ValidityDuration:       details.Duration,
		Tags:                   tags,
	})
	if errors.Is(err, ociissuer.ErrConflict) {
		resource, err = ociClient.FindCertificateByName(ctx, spec.CompartmentID, name)
		if err == nil && !ownedByRequest(resource, cr) {
			return signer.PEMBundle{}, signer.PermanentError{Err: fmt.Errorf("OCI certificate name %q already exists but is not owned by CertificateRequest %s/%s", name, cr.GetNamespace(), cr.GetName())}
		}
	}
	if err != nil {
		return signer.PEMBundle{}, classifySignError(err)
	}
	if !ownedByRequest(resource, cr) {
		return signer.PEMBundle{}, signer.PermanentError{Err: fmt.Errorf("OCI certificate %s is missing ownership tags for CertificateRequest %s/%s", resource.ID, cr.GetNamespace(), cr.GetName())}
	}

	if resource.LifecycleState != ociissuer.LifecycleActive {
		resource, err = ociClient.GetCertificate(ctx, resource.ID)
		if err != nil {
			return signer.PEMBundle{}, classifySignError(err)
		}
	}
	switch resource.LifecycleState {
	case ociissuer.LifecycleActive:
	case ociissuer.LifecycleCreating, "":
		return signer.PEMBundle{}, signer.PendingError{Err: fmt.Errorf("OCI certificate %s is not active yet", resource.ID), RequeueAfter: defaultCreatingRequeue}
	case ociissuer.LifecycleFailed:
		return signer.PEMBundle{}, signer.PermanentError{Err: fmt.Errorf("OCI certificate %s entered FAILED state", resource.ID)}
	default:
		return signer.PEMBundle{}, signer.PendingError{Err: fmt.Errorf("OCI certificate %s is %s", resource.ID, resource.LifecycleState), RequeueAfter: defaultPendingRequeue}
	}

	bundle, err := ociClient.GetCertificateBundle(ctx, resource.ID)
	if err != nil {
		return signer.PEMBundle{}, classifySignError(err)
	}
	chainPEM := []byte(strings.TrimSpace(bundle.CertificatePEM) + "\n" + strings.TrimSpace(bundle.ChainPEM) + "\n")
	certs, err := decodeCertificateChainPEM(chainPEM)
	if err != nil {
		return signer.PEMBundle{}, signer.PermanentError{Err: err}
	}
	if err := validateIssuedCertificate(validated.CSR, details, certs, requestStart); err != nil {
		return signer.PEMBundle{}, signer.PermanentError{Err: err}
	}
	parsed, err := pki.ParseSingleCertificateChainPEM(chainPEM)
	if err != nil {
		return signer.PEMBundle{}, signer.PermanentError{Err: fmt.Errorf("parse OCI certificate bundle: %w", err)}
	}

	if err := scheduleDeletion(ctx, ociClient, cleanupPolicy(i.CleanupPolicy), resource.ID, time.Now); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "failed to schedule OCI certificate deletion", "certificateID", resource.ID)
	}

	return signer.PEMBundle(parsed), nil
}

func classifySignError(err error) error {
	if errors.Is(err, ociissuer.ErrRetryable) || errors.Is(err, ociissuer.ErrNotFound) {
		return signer.PendingError{Err: err, RequeueAfter: defaultPendingRequeue}
	}
	if errors.Is(err, ociissuer.ErrInvalid) {
		return signer.PermanentError{Err: err}
	}
	if errors.Is(err, ociissuer.ErrUnauthorized) {
		return signer.IssuerError{Err: err}
	}
	return err
}

func certificateName(uid types.UID) string {
	return "oci-cas-" + string(uid)
}

func requestTags(cr signer.CertificateRequestObject) map[string]string {
	return map[string]string{
		tagRequestUID:       string(cr.GetUID()),
		tagRequestNamespace: cr.GetNamespace(),
		tagRequestName:      cr.GetName(),
		tagManaged:          tagManagedValue,
	}
}

func ownedByRequest(resource ociissuer.CertificateResource, cr signer.CertificateRequestObject) bool {
	return resource.Tags[tagManaged] == tagManagedValue &&
		resource.Tags[tagRequestUID] == string(cr.GetUID()) &&
		resource.Tags[tagRequestNamespace] == cr.GetNamespace() &&
		resource.Tags[tagRequestName] == cr.GetName()
}

func cleanupPolicy(policy CleanupPolicy) CleanupPolicy {
	if policy.DeleteAfter <= 0 {
		return DefaultCleanupPolicy()
	}
	return policy
}

func APIKeySecretNamespace(kind string, issuerNamespace, clusterResourceNamespace string) string {
	if kind == "OCIClusterIssuer" {
		return clusterResourceNamespace
	}
	return issuerNamespace
}

var _ = corev1.Secret{}
