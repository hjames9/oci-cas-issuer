package oci

import (
	"context"
	"errors"
	"time"
)

type LifecycleState string

const (
	LifecycleCreating LifecycleState = "CREATING"
	LifecycleActive   LifecycleState = "ACTIVE"
	LifecycleFailed   LifecycleState = "FAILED"
)

var (
	ErrNotFound     = errors.New("oci resource not found")
	ErrConflict     = errors.New("oci resource already exists")
	ErrRetryable    = errors.New("oci retryable error")
	ErrUnauthorized = errors.New("oci unauthorized")
	ErrInvalid      = errors.New("oci invalid request")
)

type IssueRequest struct {
	CompartmentID          string
	CertificateAuthorityID string
	Name                   string
	CSRPem                 string
	ValidityDuration       time.Duration
	Tags                   map[string]string
}

type CertificateResource struct {
	ID             string
	Name           string
	LifecycleState LifecycleState
	Tags           map[string]string
}

type CertificateBundle struct {
	CertificatePEM string
	ChainPEM       string
}

type Client interface {
	CheckCertificateAuthority(ctx context.Context, certificateAuthorityID string) error
	CreateCertificate(ctx context.Context, req IssueRequest) (CertificateResource, error)
	GetCertificate(ctx context.Context, certificateID string) (CertificateResource, error)
	FindCertificateByName(ctx context.Context, compartmentID, name string) (CertificateResource, error)
	ListManagedCertificates(ctx context.Context, compartmentID string) ([]CertificateResource, error)
	GetCertificateBundle(ctx context.Context, certificateID string) (CertificateBundle, error)
	ScheduleCertificateDeletion(ctx context.Context, certificateID string, deleteAt time.Time) error
}

type Factory interface {
	ForIssuer(ctx context.Context, namespace string, spec interface{}) (Client, error)
}
