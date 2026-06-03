package controller

import (
	"context"
	"time"

	ociissuer "github.com/oci-cert-manager/oci-cas-issuer/internal/oci"
)

type GarbageCollector struct {
	Client      ociissuer.Client
	Compartment string
	DeleteAfter time.Duration
	Now         func() time.Time
}

func (g GarbageCollector) RunOnce(ctx context.Context) (int, error) {
	if g.Client == nil {
		return 0, nil
	}
	now := g.Now
	if now == nil {
		now = time.Now
	}
	deleteAfter := g.DeleteAfter
	if deleteAfter <= 0 {
		deleteAfter = DefaultDeleteWait
	}
	certs, err := g.Client.ListManagedCertificates(ctx, g.Compartment)
	if err != nil {
		return 0, err
	}
	var scheduled int
	for _, cert := range certs {
		if cert.Tags[tagManaged] != tagManagedValue {
			continue
		}
		if err := g.Client.ScheduleCertificateDeletion(ctx, cert.ID, now().Add(deleteAfter)); err != nil {
			return scheduled, err
		}
		scheduled++
	}
	return scheduled, nil
}
