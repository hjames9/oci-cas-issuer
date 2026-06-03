package oci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/certificates"
	certsmgmt "github.com/oracle/oci-go-sdk/v65/certificatesmanagement"
	"github.com/oracle/oci-go-sdk/v65/common"
)

type RealClient struct {
	management *certsmgmt.CertificatesManagementClient
	retrieval  *certificates.CertificatesClient
}

type sdkClientConstructors struct {
	management func(common.ConfigurationProvider) (certsmgmt.CertificatesManagementClient, error)
	retrieval  func(common.ConfigurationProvider) (certificates.CertificatesClient, error)
}

func NewRealClient(provider common.ConfigurationProvider, region string) (*RealClient, error) {
	return newRealClient(provider, region, sdkClientConstructors{
		management: certsmgmt.NewCertificatesManagementClientWithConfigurationProvider,
		retrieval:  certificates.NewCertificatesClientWithConfigurationProvider,
	})
}

func newRealClient(provider common.ConfigurationProvider, region string, constructors sdkClientConstructors) (*RealClient, error) {
	management, err := constructors.management(provider)
	if err != nil {
		return nil, err
	}
	retrieval, err := constructors.retrieval(provider)
	if err != nil {
		return nil, err
	}
	if region != "" {
		management.SetRegion(region)
		retrieval.SetRegion(region)
	}
	return &RealClient{management: &management, retrieval: &retrieval}, nil
}

func (c *RealClient) CheckCertificateAuthority(ctx context.Context, certificateAuthorityID string) error {
	_, err := c.management.GetCertificateAuthority(ctx, certsmgmt.GetCertificateAuthorityRequest{
		CertificateAuthorityId: common.String(certificateAuthorityID),
	})
	return classify(err)
}

func (c *RealClient) CreateCertificate(ctx context.Context, req IssueRequest) (CertificateResource, error) {
	resp, err := c.management.CreateCertificate(ctx, certsmgmt.CreateCertificateRequest{
		CreateCertificateDetails: createCertificateDetails(req, time.Now),
	})
	if err != nil {
		return CertificateResource{}, classify(err)
	}
	return certificateResource(resp.Certificate), nil
}

func (c *RealClient) GetCertificate(ctx context.Context, certificateID string) (CertificateResource, error) {
	resp, err := c.management.GetCertificate(ctx, certsmgmt.GetCertificateRequest{CertificateId: common.String(certificateID)})
	if err != nil {
		return CertificateResource{}, classify(err)
	}
	return certificateResource(resp.Certificate), nil
}

func (c *RealClient) FindCertificateByName(ctx context.Context, compartmentID, name string) (CertificateResource, error) {
	resp, err := c.management.ListCertificates(ctx, certsmgmt.ListCertificatesRequest{
		CompartmentId: common.String(compartmentID),
		Name:          common.String(name),
	})
	if err != nil {
		return CertificateResource{}, classify(err)
	}
	for _, item := range resp.CertificateCollection.Items {
		if value(item.Name) == name {
			return certificateSummaryResource(item), nil
		}
	}
	return CertificateResource{}, ErrNotFound
}

func (c *RealClient) ListManagedCertificates(ctx context.Context, compartmentID string) ([]CertificateResource, error) {
	resp, err := c.management.ListCertificates(ctx, certsmgmt.ListCertificatesRequest{
		CompartmentId: common.String(compartmentID),
	})
	if err != nil {
		return nil, classify(err)
	}
	certs := make([]CertificateResource, 0, len(resp.CertificateCollection.Items))
	for _, item := range resp.CertificateCollection.Items {
		certs = append(certs, certificateSummaryResource(item))
	}
	return certs, nil
}

func (c *RealClient) GetCertificateBundle(ctx context.Context, certificateID string) (CertificateBundle, error) {
	resp, err := c.retrieval.GetCertificateBundle(ctx, certificates.GetCertificateBundleRequest{
		CertificateId: common.String(certificateID),
		Stage:         certificates.GetCertificateBundleStageCurrent,
	})
	if err != nil {
		return CertificateBundle{}, classify(err)
	}
	return CertificateBundle{
		CertificatePEM: value(resp.CertificateBundle.GetCertificatePem()),
		ChainPEM:       value(resp.CertificateBundle.GetCertChainPem()),
	}, nil
}

func (c *RealClient) ScheduleCertificateDeletion(ctx context.Context, certificateID string, deleteAt time.Time) error {
	_, err := c.management.ScheduleCertificateDeletion(ctx, certsmgmt.ScheduleCertificateDeletionRequest{
		CertificateId: common.String(certificateID),
		ScheduleCertificateDeletionDetails: certsmgmt.ScheduleCertificateDeletionDetails{
			TimeOfDeletion: &common.SDKTime{Time: deleteAt.UTC()},
		},
	})
	return classify(err)
}

func createCertificateDetails(req IssueRequest, now func() time.Time) certsmgmt.CreateCertificateDetails {
	config := createManagedExternallyIssuedByInternalCAConfig{
		IssuerCertificateAuthorityId: common.String(req.CertificateAuthorityID),
		CsrPem:                       common.String(req.CSRPem),
		VersionName:                  common.String(req.Name),
	}
	if req.ValidityDuration > 0 {
		start := now().UTC()
		config.Validity = &validityWire{
			TimeOfValidityNotBefore: formatOCITime(start.Add(-5 * time.Minute)),
			TimeOfValidityNotAfter:  formatOCITime(start.Add(req.ValidityDuration)),
		}
	}
	return certsmgmt.CreateCertificateDetails{
		Name:              common.String(req.Name),
		CompartmentId:     common.String(req.CompartmentID),
		CertificateConfig: config,
		FreeformTags:      req.Tags,
	}
}

type createManagedExternallyIssuedByInternalCAConfig struct {
	IssuerCertificateAuthorityId *string       `json:"issuerCertificateAuthorityId"`
	CsrPem                       *string       `json:"csrPem"`
	VersionName                  *string       `json:"versionName,omitempty"`
	Validity                     *validityWire `json:"validity,omitempty"`
}

func (c createManagedExternallyIssuedByInternalCAConfig) GetVersionName() *string {
	return c.VersionName
}

func (c createManagedExternallyIssuedByInternalCAConfig) MarshalJSON() ([]byte, error) {
	type wire createManagedExternallyIssuedByInternalCAConfig
	return json.Marshal(struct {
		ConfigType string `json:"configType"`
		wire
	}{
		ConfigType: "MANAGED_EXTERNALLY_ISSUED_BY_INTERNAL_CA",
		wire:       wire(c),
	})
}

type validityWire struct {
	TimeOfValidityNotAfter  string `json:"timeOfValidityNotAfter"`
	TimeOfValidityNotBefore string `json:"timeOfValidityNotBefore,omitempty"`
}

func formatOCITime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000+00:00")
}

func certificateResource(cert certsmgmt.Certificate) CertificateResource {
	return CertificateResource{
		ID:             value(cert.Id),
		Name:           value(cert.Name),
		LifecycleState: LifecycleState(string(cert.LifecycleState)),
		Tags:           cert.FreeformTags,
	}
}

func certificateSummaryResource(item certsmgmt.CertificateSummary) CertificateResource {
	return CertificateResource{
		ID:             value(item.Id),
		Name:           value(item.Name),
		LifecycleState: LifecycleState(string(item.LifecycleState)),
		Tags:           item.FreeformTags,
	}
}

func classify(err error) error {
	if err == nil {
		return nil
	}
	var serviceErr common.ServiceError
	if errors.As(err, &serviceErr) {
		switch serviceErr.GetHTTPStatusCode() {
		case 404:
			return fmt.Errorf("%w: %v", ErrNotFound, err)
		case 409:
			return fmt.Errorf("%w: %v", ErrConflict, err)
		case 400, 422:
			if strings.Contains(strings.ToLower(serviceErr.GetMessage()), "already exists") {
				return fmt.Errorf("%w: %v", ErrConflict, err)
			}
			return fmt.Errorf("%w: %v", ErrInvalid, err)
		case 401, 403:
			return fmt.Errorf("%w: %v", ErrUnauthorized, err)
		case 429, 500, 502, 503, 504:
			return fmt.Errorf("%w: %v", ErrRetryable, err)
		}
	}
	return err
}

func value(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
