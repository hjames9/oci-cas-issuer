package v1alpha1

import (
	"testing"

	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestIssuerHelpers(t *testing.T) {
	issuer := &OCIIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "issuer"},
		Status:     statusWithReadyCondition(),
	}
	require.Equal(t, issuer.Status.Conditions, issuer.GetConditions())
	require.Equal(t, "ociissuers.cas.oci-issuer.cert-manager.io", issuer.GetIssuerTypeIdentifier())

	clusterIssuer := &OCIClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-issuer"},
		Status:     statusWithReadyCondition(),
	}
	require.Equal(t, clusterIssuer.Status.Conditions, clusterIssuer.GetConditions())
	require.Equal(t, "ociclusterissuers.cas.oci-issuer.cert-manager.io", clusterIssuer.GetIssuerTypeIdentifier())
}

func TestDeepCopy(t *testing.T) {
	issuer := &OCIIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "issuer", Namespace: "default"},
		Spec: IssuerSpec{
			CertificateAuthorityID: "ca",
			CompartmentID:          "compartment",
			Region:                 "us-ashburn-1",
			Auth: OCIAuth{
				Type:            AuthTypeAPIKey,
				APIKeySecretRef: &SecretKeySelector{Name: "secret"},
			},
		},
		Status: statusWithReadyCondition(),
	}
	issuerCopy := issuer.DeepCopy()
	require.Equal(t, issuer, issuerCopy)
	require.NotSame(t, issuer, issuerCopy)
	require.NotSame(t, issuer.Spec.Auth.APIKeySecretRef, issuerCopy.Spec.Auth.APIKeySecretRef)
	require.NotNil(t, issuer.DeepCopyObject())

	clusterIssuer := &OCIClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-issuer"},
		Spec:       issuer.Spec,
		Status:     statusWithReadyCondition(),
	}
	require.Equal(t, clusterIssuer, clusterIssuer.DeepCopy())
	require.NotNil(t, clusterIssuer.DeepCopyObject())

	issuerList := &OCIIssuerList{Items: []OCIIssuer{*issuer}}
	require.Equal(t, issuerList, issuerList.DeepCopy())
	require.NotNil(t, issuerList.DeepCopyObject())

	clusterIssuerList := &OCIClusterIssuerList{Items: []OCIClusterIssuer{*clusterIssuer}}
	require.Equal(t, clusterIssuerList, clusterIssuerList.DeepCopy())
	require.NotNil(t, clusterIssuerList.DeepCopyObject())

	selector := &SecretKeySelector{Name: "secret"}
	require.Equal(t, selector, selector.DeepCopy())

	spec := &IssuerSpec{Auth: OCIAuth{APIKeySecretRef: &SecretKeySelector{Name: "secret"}}}
	require.Equal(t, spec, spec.DeepCopy())
	auth := &OCIAuth{APIKeySecretRef: &SecretKeySelector{Name: "secret"}}
	require.Equal(t, auth, auth.DeepCopy())

	var nilSpec *IssuerSpec
	require.Nil(t, nilSpec.DeepCopy())
	var nilAuth *OCIAuth
	require.Nil(t, nilAuth.DeepCopy())
	var nilIssuer *OCIIssuer
	require.Nil(t, nilIssuer.DeepCopy())
	require.Nil(t, nilIssuer.DeepCopyObject())
	var nilClusterIssuer *OCIClusterIssuer
	require.Nil(t, nilClusterIssuer.DeepCopy())
	require.Nil(t, nilClusterIssuer.DeepCopyObject())
	var nilIssuerList *OCIIssuerList
	require.Nil(t, nilIssuerList.DeepCopy())
	require.Nil(t, nilIssuerList.DeepCopyObject())
	var nilClusterIssuerList *OCIClusterIssuerList
	require.Nil(t, nilClusterIssuerList.DeepCopy())
	require.Nil(t, nilClusterIssuerList.DeepCopyObject())
	var nilSelector *SecretKeySelector
	require.Nil(t, nilSelector.DeepCopy())
}

func TestAddToSchemeRegistersIssuerTypes(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, AddToScheme(scheme))

	for _, tc := range []struct {
		name string
		obj  runtime.Object
		kind string
	}{
		{name: "issuer", obj: &OCIIssuer{}, kind: "OCIIssuer"},
		{name: "issuer list", obj: &OCIIssuerList{}, kind: "OCIIssuerList"},
		{name: "cluster issuer", obj: &OCIClusterIssuer{}, kind: "OCIClusterIssuer"},
		{name: "cluster issuer list", obj: &OCIClusterIssuerList{}, kind: "OCIClusterIssuerList"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kinds, _, err := scheme.ObjectKinds(tc.obj)
			require.NoError(t, err)
			require.Contains(t, kinds, GroupVersion.WithKind(tc.kind))
		})
	}
}

func statusWithReadyCondition() issuerapi.IssuerStatus {
	return issuerapi.IssuerStatus{Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Ready", Message: "ready", LastTransitionTime: metav1.Now()}}}
}
