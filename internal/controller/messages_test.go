package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/cert-manager/issuer-lib/controllers/signer"
	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/require"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"

	casv1alpha1 "github.com/oci-cert-manager/oci-cas-issuer/api/v1alpha1"
	ociissuer "github.com/oci-cert-manager/oci-cas-issuer/internal/oci"
)

func TestTruncateMessage(t *testing.T) {
	for _, message := range []string{"", "short message", strings.Repeat("a", 1024), strings.Repeat("a", 1025), strings.Repeat("a", 1009) + strings.Repeat("\u20ac", 20), strings.Repeat("\U0001f600", 300)} {
		t.Run(fmt.Sprintf("bytes-%d", len(message)), func(t *testing.T) {
			got := truncateMessage(message, maxEventMessageBytes)
			require.LessOrEqual(t, len(got), 1024)
			require.True(t, utf8.ValidString(got))
			if len(message) <= 1024 {
				require.Equal(t, message, got)
			} else {
				require.True(t, strings.HasSuffix(got, truncationMarker))
				require.True(t, strings.HasPrefix(message, strings.TrimSuffix(got, truncationMarker)))
			}
		})
	}
}

func TestBoundedEventRecorder(t *testing.T) {
	for _, obj := range []runtime.Object{controllerCertificateRequest("test", nil, true), &certificatesv1.CertificateSigningRequest{}, &casv1alpha1.OCIIssuer{}, &casv1alpha1.OCIClusterIssuer{}, &runtime.Unknown{}} {
		for _, eventType := range []string{corev1.EventTypeWarning, corev1.EventTypeNormal} {
			recorder := events.NewFakeRecorder(1)
			wrapped := Issuer{}.combinedController(recorder).EventRecorder
			for _, message := range []string{"short 100% message", strings.Repeat("\u20ac", 500)} {
				wrapped.Eventf(obj, nil, eventType, "Failed", "Sync", "OCI error: %s", message)
				got := strings.TrimPrefix(<-recorder.Events, eventType+" Failed ")
				require.Equal(t, truncateMessage("OCI error: "+message, 1024), got)
				require.LessOrEqual(t, len(got), 1024)
				require.True(t, utf8.ValidString(got))
			}
			wrapped.Eventf(obj, nil, eventType, "Failed", "Sync", "literal 100% message")
			require.Equal(t, eventType+" Failed literal 100% message", <-recorder.Events)
		}
	}
}

func TestReportControllerError(t *testing.T) {
	var logs []string
	logger := funcr.New(func(_, message string) { logs = append(logs, message) }, funcr.Options{})
	ctx := ctrl.LoggerInto(context.Background(), logger)
	require.NoError(t, reportControllerError(ctx, nil, "test"))
	short := errors.New("short")
	require.Same(t, short, reportControllerError(ctx, short, "test"))

	cause := errors.New(strings.Repeat("\u20ac", 12000) + " full-detail-tail")
	for _, err := range []error{cause, signer.PendingError{Err: cause, RequeueAfter: 10 * time.Second}, signer.PermanentError{Err: cause}, signer.IssuerError{Err: cause}} {
		got := reportControllerError(ctx, err, "test failure")
		require.LessOrEqual(t, len(got.Error()), maxErrorMessageBytes)
		require.True(t, utf8.ValidString(got.Error()))
		require.ErrorIs(t, got, cause)
		var pending signer.PendingError
		if errors.As(err, &pending) {
			var actual signer.PendingError
			require.ErrorAs(t, got, &actual)
			require.Equal(t, pending.RequeueAfter, actual.RequeueAfter)
		}
		var permanent signer.PermanentError
		if errors.As(err, &permanent) {
			require.ErrorAs(t, got, &permanent)
		}
		var issuerErr signer.IssuerError
		if errors.As(err, &issuerErr) {
			require.ErrorAs(t, got, &issuerErr)
			require.LessOrEqual(t, len(issuerErr.Err.Error()), maxErrorMessageBytes)
			require.ErrorIs(t, issuerErr.Err, cause)
		}
		require.Contains(t, logs[len(logs)-1], cause.Error())
	}
}

func TestSignAndCheckLogFullErrors(t *testing.T) {
	var logs []string
	logger := funcr.New(func(_, message string) { logs = append(logs, message) }, funcr.Options{})
	ctx := ctrl.LoggerInto(context.Background(), logger)
	cause := errors.New(strings.Repeat("x", 40000) + " full-detail-tail")
	fakeOCI := ociissuer.NewFakeClient()
	fakeOCI.CAError = cause
	fakeOCI.CreateError = fmt.Errorf("%w: %w", ociissuer.ErrRetryable, cause)
	issuer := Issuer{ClientFactory: staticFactory{client: fakeOCI}}
	err := issuer.Check(ctx, issuerObject())
	require.ErrorIs(t, err, cause)
	require.LessOrEqual(t, len(err.Error()), maxErrorMessageBytes)
	require.Contains(t, logs[len(logs)-1], cause.Error())
	_, err = issuer.Sign(ctx, requestObject(testCSR(t)), issuerObject())
	var pending signer.PendingError
	require.ErrorAs(t, err, &pending)
	require.Equal(t, defaultPendingRequeue, pending.RequeueAfter)
	require.LessOrEqual(t, len(err.Error()), maxErrorMessageBytes)
	require.Contains(t, logs[len(logs)-1], cause.Error())
}

func TestCertificateRequestControllerBoundsOCIErrorMessages(t *testing.T) {
	fakeOCI := ociissuer.NewFakeClient()
	fakeOCI.CreateError = fmt.Errorf("%w: %s", ociissuer.ErrInvalid, strings.Repeat("x", 40000))
	cr := controllerCertificateRequest("long-error", testCSR(t), true)
	kubeClient := controllerFakeClient(t, cr, readyControllerIssuer())
	reconciler := controllerCertificateRequestReconciler(t, kubeClient, fakeOCI)
	recorder := events.NewFakeRecorder(10)
	reconciler.EventRecorder = Issuer{}.combinedController(recorder).EventRecorder

	require.Error(t, reconcileCertificateRequestTwice(t, reconciler, cr))
	got := getControllerCertificateRequest(t, kubeClient, cr.Name)
	ready := controllerCertificateRequestReadyCondition(t, got)
	require.NotNil(t, ready)
	require.Equal(t, "Failed", ready.Reason)
	require.LessOrEqual(t, len(ready.Message), 32768)
	require.Contains(t, ready.Message, truncationMarker)
	require.NotNil(t, got.Status.FailureTime)
	require.Empty(t, got.Status.Certificate)
	require.NotEmpty(t, recorder.Events)
	for len(recorder.Events) > 0 {
		message := strings.SplitN(<-recorder.Events, " ", 3)[2]
		require.LessOrEqual(t, len(message), 1024)
		require.True(t, utf8.ValidString(message))
	}
}
