package oci

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFakeClientLifecycle(t *testing.T) {
	client := NewFakeClient()
	require.NoError(t, client.CheckCertificateAuthority(context.Background(), "ca"))

	req := IssueRequest{
		CompartmentID:          "compartment",
		CertificateAuthorityID: "ca",
		Name:                   "cert",
		CSRPem:                 "csr",
		Tags:                   map[string]string{"managed": "true"},
	}
	cert, err := client.CreateCertificate(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "cert", cert.Name)
	require.Equal(t, LifecycleActive, cert.LifecycleState)

	_, err = client.CreateCertificate(context.Background(), req)
	require.ErrorIs(t, err, ErrConflict)

	got, err := client.GetCertificate(context.Background(), cert.ID)
	require.NoError(t, err)
	require.Equal(t, cert, got)

	found, err := client.FindCertificateByName(context.Background(), "compartment", "cert")
	require.NoError(t, err)
	require.Equal(t, cert, found)

	listed, err := client.ListManagedCertificates(context.Background(), "compartment")
	require.NoError(t, err)
	require.Len(t, listed, 1)

	client.Bundles[cert.ID] = CertificateBundle{CertificatePEM: "leaf", ChainPEM: "chain"}
	bundle, err := client.GetCertificateBundle(context.Background(), cert.ID)
	require.NoError(t, err)
	require.Equal(t, "leaf", bundle.CertificatePEM)

	require.NoError(t, client.ScheduleCertificateDeletion(context.Background(), cert.ID, time.Now()))
	require.Equal(t, []string{cert.ID}, client.Deleted)

	second, err := client.CreateCertificate(context.Background(), IssueRequest{Name: "second"})
	require.NoError(t, err)
	require.Contains(t, second.ID, ".2")
}

func TestFakeClientErrors(t *testing.T) {
	client := NewFakeClient()
	client.CAError = ErrUnauthorized
	require.ErrorIs(t, client.CheckCertificateAuthority(context.Background(), "ca"), ErrUnauthorized)

	client.CreateError = ErrInvalid
	_, err := client.CreateCertificate(context.Background(), IssueRequest{Name: "cert"})
	require.ErrorIs(t, err, ErrInvalid)

	_, err = client.GetCertificate(context.Background(), "missing")
	require.ErrorIs(t, err, ErrNotFound)

	_, err = client.FindCertificateByName(context.Background(), "compartment", "missing")
	require.ErrorIs(t, err, ErrNotFound)

	_, err = client.GetCertificateBundle(context.Background(), "missing")
	require.ErrorIs(t, err, ErrNotFound)

	client.BundleError = ErrRetryable
	_, err = client.GetCertificateBundle(context.Background(), "missing")
	require.ErrorIs(t, err, ErrRetryable)

	client.DeleteError = ErrConflict
	require.ErrorIs(t, client.ScheduleCertificateDeletion(context.Background(), "cert", time.Now()), ErrConflict)
}
