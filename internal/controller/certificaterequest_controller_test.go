package controller

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"reflect"
	"testing"
	"time"
	"unsafe"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	issuercontrollers "github.com/cert-manager/issuer-lib/controllers"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	clocktesting "k8s.io/utils/clock/testing"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	casv1alpha1 "github.com/oci-cert-manager/oci-cas-issuer/api/v1alpha1"
	ociissuer "github.com/oci-cert-manager/oci-cas-issuer/internal/oci"
)

func TestCertificateRequestControllerIgnoresUnapprovedRequests(t *testing.T) {
	fakeOCI := ociissuer.NewFakeClient()
	cr := controllerCertificateRequest("unapproved", testCSR(t), false)
	kubeClient := controllerFakeClient(t, cr, readyControllerIssuer())
	reconciler := controllerCertificateRequestReconciler(t, kubeClient, fakeOCI)

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cr)})
	require.NoError(t, err)

	var got cmapi.CertificateRequest
	require.NoError(t, kubeClient.Get(context.Background(), client.ObjectKeyFromObject(cr), &got))
	require.Empty(t, got.Status.Conditions)
	require.Empty(t, fakeOCI.Created)
}

func TestCertificateRequestControllerMarksInvalidRequestsFailed(t *testing.T) {
	fakeOCI := ociissuer.NewFakeClient()
	cr := controllerCertificateRequest("invalid", []byte("not a csr"), true)
	kubeClient := controllerFakeClient(t, cr, readyControllerIssuer())
	reconciler := controllerCertificateRequestReconciler(t, kubeClient, fakeOCI)

	err := reconcileCertificateRequestTwice(t, reconciler, cr)
	require.Error(t, err)

	got := getControllerCertificateRequest(t, kubeClient, cr.Name)
	ready := controllerCertificateRequestReadyCondition(t, got)
	require.NotNil(t, ready)
	require.Equal(t, cmmeta.ConditionFalse, ready.Status)
	require.Equal(t, cmapi.CertificateRequestReasonFailed, ready.Reason)
	require.Contains(t, ready.Message, "PEM encoded CSR")
	require.Empty(t, got.Status.Certificate)
	require.NotNil(t, got.Status.FailureTime)
	require.Empty(t, fakeOCI.Created)
}

func TestCertificateRequestControllerSignsAgainstFakeOCI(t *testing.T) {
	caCert, caKey := testCA(t)
	csrPEM := testCSR(t)
	leafPEM := signCSR(t, csrPEM, caCert, caKey)
	cr := controllerCertificateRequest("valid", csrPEM, true)

	fakeOCI := ociissuer.NewFakeClient()
	fakeOCI.Bundles["ocid1.certificate.oc1.test."+certificateName(cr.UID)] = ociissuer.CertificateBundle{
		CertificatePEM: string(leafPEM),
		ChainPEM:       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})),
	}
	kubeClient := controllerFakeClient(t, cr, readyControllerIssuer())
	reconciler := controllerCertificateRequestReconciler(t, kubeClient, fakeOCI)

	err := reconcileCertificateRequestTwice(t, reconciler, cr)
	require.NoError(t, err)

	got := getControllerCertificateRequest(t, kubeClient, cr.Name)
	ready := controllerCertificateRequestReadyCondition(t, got)
	require.NotNil(t, ready)
	require.Equal(t, cmmeta.ConditionTrue, ready.Status)
	require.Equal(t, cmapi.CertificateRequestReasonIssued, ready.Reason)
	require.NotEmpty(t, got.Status.Certificate)
	require.NotEmpty(t, got.Status.CA)
	require.Len(t, fakeOCI.Created, 1)
	require.Equal(t, []string{"ocid1.certificate.oc1.test." + certificateName(cr.UID)}, fakeOCI.Deleted)
}

func TestCertificateRequestControllerRejectsOCIMismatchWithoutWritingCertificate(t *testing.T) {
	caCert, caKey := testCA(t)
	csrPEM := testCSR(t)
	leafPEM := signCSRWithMutation(t, csrPEM, caCert, caKey, func(cert *x509.Certificate) {
		cert.DNSNames = []string{"other.example.com"}
	})
	cr := controllerCertificateRequest("mismatch", csrPEM, true)

	fakeOCI := ociissuer.NewFakeClient()
	fakeOCI.Bundles["ocid1.certificate.oc1.test."+certificateName(cr.UID)] = ociissuer.CertificateBundle{
		CertificatePEM: string(leafPEM),
		ChainPEM:       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})),
	}
	kubeClient := controllerFakeClient(t, cr, readyControllerIssuer())
	reconciler := controllerCertificateRequestReconciler(t, kubeClient, fakeOCI)

	err := reconcileCertificateRequestTwice(t, reconciler, cr)
	require.Error(t, err)

	got := getControllerCertificateRequest(t, kubeClient, cr.Name)
	ready := controllerCertificateRequestReadyCondition(t, got)
	require.NotNil(t, ready)
	require.Equal(t, cmmeta.ConditionFalse, ready.Status)
	require.Equal(t, cmapi.CertificateRequestReasonFailed, ready.Reason)
	require.Contains(t, ready.Message, "DNS SANs")
	require.Empty(t, got.Status.Certificate)
}

func controllerCertificateRequestReconciler(t *testing.T, kubeClient client.Client, ociClient ociissuer.Client) *issuercontrollers.CertificateRequestReconciler {
	t.Helper()
	reconciler := (&issuercontrollers.CertificateRequestReconciler{
		SetCAOnCertificateRequest: true,
		RequestController: issuercontrollers.RequestController{
			IssuerTypes: []issuerapi.Issuer{&casv1alpha1.OCIIssuer{
				TypeMeta: metav1.TypeMeta{APIVersion: casv1alpha1.GroupVersion.String(), Kind: "OCIIssuer"},
			}},
			FieldOwner:       FieldOwner,
			MaxRetryDuration: time.Minute,
			Client:           kubeClient,
			Sign:             Issuer{ClientFactory: staticFactory{client: ociClient}}.Sign,
			EventRecorder:    record.NewFakeRecorder(100),
			Clock:            clocktesting.NewFakeClock(time.Unix(1000, 0)),
		},
	}).Init()
	setControllerIssuerTypes(t, reconciler)
	return reconciler
}

func setControllerIssuerTypes(t *testing.T, reconciler *issuercontrollers.CertificateRequestReconciler) {
	t.Helper()
	value := reflect.ValueOf(&reconciler.RequestController).Elem().FieldByName("allIssuerTypes")
	reflect.NewAt(value.Type(), unsafe.Pointer(value.UnsafeAddr())).Elem().Set(reflect.ValueOf([]issuercontrollers.IssuerType{
		{
			Type: &casv1alpha1.OCIIssuer{
				TypeMeta: metav1.TypeMeta{APIVersion: casv1alpha1.GroupVersion.String(), Kind: "OCIIssuer"},
			},
			IsNamespaced: true,
		},
	}))
}

func controllerFakeClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, cmapi.AddToScheme(scheme))
	require.NoError(t, casv1alpha1.AddToScheme(scheme))
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&cmapi.CertificateRequest{}, &casv1alpha1.OCIIssuer{}).
		WithObjects(objects...).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: applyCertificateRequestStatusPatch,
		}).
		Build()
}

func applyCertificateRequestStatusPatch(ctx context.Context, kubeClient client.Client, subResourceName string, obj client.Object, patch client.Patch, _ ...client.SubResourcePatchOption) error {
	if subResourceName != "status" {
		return fmt.Errorf("unsupported test subresource patch %q", subResourceName)
	}
	if patch.Type() != types.ApplyPatchType {
		return fmt.Errorf("unsupported test status patch type %q", patch.Type())
	}

	data, err := patch.Data(obj)
	if err != nil {
		return err
	}
	var patched cmapi.CertificateRequest
	if err := json.Unmarshal(data, &patched); err != nil {
		return err
	}
	var current cmapi.CertificateRequest
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(obj), &current); err != nil {
		return err
	}
	mergeCertificateRequestStatus(&current.Status, patched.Status)
	return kubeClient.Status().Update(ctx, &current)
}

func mergeCertificateRequestStatus(current *cmapi.CertificateRequestStatus, patched cmapi.CertificateRequestStatus) {
	if len(patched.Certificate) > 0 {
		current.Certificate = patched.Certificate
	}
	if len(patched.CA) > 0 {
		current.CA = patched.CA
	}
	if patched.FailureTime != nil {
		current.FailureTime = patched.FailureTime
	}
	if len(patched.Conditions) > 0 {
		current.Conditions = mergeCertificateRequestConditions(current.Conditions, patched.Conditions)
	}
}

func mergeCertificateRequestConditions(current, patched []cmapi.CertificateRequestCondition) []cmapi.CertificateRequestCondition {
	merged := append([]cmapi.CertificateRequestCondition(nil), current...)
	for _, patchCondition := range patched {
		replaced := false
		for i := range merged {
			if merged[i].Type == patchCondition.Type {
				merged[i] = patchCondition
				replaced = true
				break
			}
		}
		if !replaced {
			merged = append(merged, patchCondition)
		}
	}
	return merged
}

func readyControllerIssuer() *casv1alpha1.OCIIssuer {
	return &casv1alpha1.OCIIssuer{
		TypeMeta:   metav1.TypeMeta{APIVersion: casv1alpha1.GroupVersion.String(), Kind: "OCIIssuer"},
		ObjectMeta: metav1.ObjectMeta{Name: "issuer", Namespace: "default", Generation: 1},
		Spec:       issuerObject().Spec,
		Status: issuerapi.IssuerStatus{Conditions: []metav1.Condition{
			{
				Type:               issuerapi.IssuerConditionTypeReady,
				Status:             metav1.ConditionTrue,
				Reason:             issuerapi.IssuerConditionReasonChecked,
				Message:            "ready",
				ObservedGeneration: 1,
				LastTransitionTime: metav1.NewTime(time.Unix(900, 0)),
			},
		}},
	}
}

func controllerCertificateRequest(name string, csr []byte, approved bool) *cmapi.CertificateRequest {
	cr := &cmapi.CertificateRequest{
		TypeMeta: metav1.TypeMeta{APIVersion: "cert-manager.io/v1", Kind: "CertificateRequest"},
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         "default",
			UID:               types.UID(name + "-uid"),
			CreationTimestamp: metav1.NewTime(time.Unix(900, 0)),
		},
		Spec: cmapi.CertificateRequestSpec{
			Request:  csr,
			Duration: &metav1.Duration{Duration: 24 * time.Hour},
			IssuerRef: cmmeta.ObjectReference{
				Group: casv1alpha1.GroupName,
				Kind:  "OCIIssuer",
				Name:  "issuer",
			},
		},
	}
	if approved {
		cr.Status.Conditions = append(cr.Status.Conditions, cmapi.CertificateRequestCondition{
			Type:               cmapi.CertificateRequestConditionApproved,
			Status:             cmmeta.ConditionTrue,
			Reason:             "Approved",
			Message:            "approved",
			LastTransitionTime: &metav1.Time{Time: time.Unix(900, 0)},
		})
	}
	return cr
}

func reconcileCertificateRequestTwice(t *testing.T, reconciler *issuercontrollers.CertificateRequestReconciler, cr *cmapi.CertificateRequest) error {
	t.Helper()
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(cr)}
	_, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	_, err = reconciler.Reconcile(context.Background(), req)
	return err
}

func getControllerCertificateRequest(t *testing.T, kubeClient client.Client, name string) *cmapi.CertificateRequest {
	t.Helper()
	var got cmapi.CertificateRequest
	require.NoError(t, kubeClient.Get(context.Background(), client.ObjectKey{Name: name, Namespace: "default"}, &got))
	return &got
}

func controllerCertificateRequestReadyCondition(t *testing.T, cr *cmapi.CertificateRequest) *cmapi.CertificateRequestCondition {
	t.Helper()
	for i := range cr.Status.Conditions {
		if cr.Status.Conditions[i].Type == cmapi.CertificateRequestConditionReady {
			return &cr.Status.Conditions[i]
		}
	}
	return nil
}
