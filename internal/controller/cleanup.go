package controller

import (
	"context"
	"fmt"
	"time"

	ociissuer "github.com/oci-cert-manager/oci-cas-issuer/internal/oci"
)

type CleanupPolicy struct {
	DeleteAfter time.Duration
}

func DefaultCleanupPolicy() CleanupPolicy {
	return CleanupPolicy{DeleteAfter: DefaultDeleteWait}
}

func scheduleDeletion(ctx context.Context, client ociissuer.Client, policy CleanupPolicy, certificateID string, now func() time.Time) error {
	deleteAfter := policy.DeleteAfter
	if deleteAfter <= 0 {
		deleteAfter = DefaultDeleteWait
	}
	if err := client.ScheduleCertificateDeletion(ctx, certificateID, now().Add(deleteAfter)); err != nil {
		return fmt.Errorf("schedule OCI certificate deletion: %w", err)
	}
	return nil
}
