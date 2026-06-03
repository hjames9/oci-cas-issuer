package oci

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type FakeClient struct {
	mu sync.Mutex

	CAError      error
	CreateError  error
	BundleError  error
	DeleteError  error
	Certificates map[string]CertificateResource
	Bundles      map[string]CertificateBundle
	Created      []IssueRequest
	Deleted      []string
	NextID       int
}

func NewFakeClient() *FakeClient {
	return &FakeClient{
		Certificates: map[string]CertificateResource{},
		Bundles:      map[string]CertificateBundle{},
		NextID:       1,
	}
}

func (f *FakeClient) CheckCertificateAuthority(context.Context, string) error {
	return f.CAError
}

func (f *FakeClient) CreateCertificate(_ context.Context, req IssueRequest) (CertificateResource, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.CreateError != nil {
		return CertificateResource{}, f.CreateError
	}
	for _, cert := range f.Certificates {
		if cert.Name == req.Name {
			return CertificateResource{}, ErrConflict
		}
	}
	id := "ocid1.certificate.oc1.test." + req.Name
	if f.NextID > 1 {
		id = fmt.Sprintf("%s.%d", id, f.NextID)
	}
	cert := CertificateResource{ID: id, Name: req.Name, LifecycleState: LifecycleActive, Tags: req.Tags}
	f.Certificates[id] = cert
	f.Created = append(f.Created, req)
	f.NextID++
	return cert, nil
}

func (f *FakeClient) GetCertificate(_ context.Context, certificateID string) (CertificateResource, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cert, ok := f.Certificates[certificateID]
	if !ok {
		return CertificateResource{}, ErrNotFound
	}
	return cert, nil
}

func (f *FakeClient) FindCertificateByName(_ context.Context, _, name string) (CertificateResource, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, cert := range f.Certificates {
		if cert.Name == name {
			return cert, nil
		}
	}
	return CertificateResource{}, ErrNotFound
}

func (f *FakeClient) ListManagedCertificates(_ context.Context, _ string) ([]CertificateResource, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	certs := make([]CertificateResource, 0, len(f.Certificates))
	for _, cert := range f.Certificates {
		certs = append(certs, cert)
	}
	return certs, nil
}

func (f *FakeClient) GetCertificateBundle(_ context.Context, certificateID string) (CertificateBundle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.BundleError != nil {
		return CertificateBundle{}, f.BundleError
	}
	bundle, ok := f.Bundles[certificateID]
	if !ok {
		return CertificateBundle{}, ErrNotFound
	}
	return bundle, nil
}

func (f *FakeClient) ScheduleCertificateDeletion(_ context.Context, certificateID string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.DeleteError != nil {
		return f.DeleteError
	}
	f.Deleted = append(f.Deleted, certificateID)
	return nil
}
