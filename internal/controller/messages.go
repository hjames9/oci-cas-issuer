package controller

import (
	"context"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/cert-manager/issuer-lib/controllers/signer"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	maxEventMessageBytes = 1024
	// Leave room for issuer-lib's prefixes within the 32768-character condition limit.
	maxErrorMessageBytes = 32768 - 1024
	truncationMarker     = "... (truncated)"
)

func truncateMessage(message string, limit int) string {
	if len(message) <= limit {
		return message
	}
	end := limit - len(truncationMarker)
	for !utf8.RuneStart(message[end]) {
		end--
	}
	return message[:end] + truncationMarker
}

// issuer-lib shares this recorder across both request controllers and both issuer scopes.
type boundedEventRecorder struct {
	events.EventRecorder
}

func (r boundedEventRecorder) Eventf(regarding, related runtime.Object, eventType, reason, action, note string, args ...interface{}) {
	message := note
	if len(args) > 0 {
		message = fmt.Sprintf(note, args...)
	}
	if len(message) > maxEventMessageBytes {
		logger := ctrl.Log.WithName("events").WithValues("object", regarding.GetObjectKind().GroupVersionKind().String(), "reason", reason, "action", action)
		if obj, ok := regarding.(interface {
			GetName() string
			GetNamespace() string
		}); ok {
			logger = logger.WithValues("name", obj.GetName(), "namespace", obj.GetNamespace())
		}
		if eventType == corev1.EventTypeWarning {
			logger.Error(errors.New(message), "Truncating Kubernetes event message")
		} else {
			logger.Info("Truncating Kubernetes event message", "message", message)
		}
	}
	// A literal format prevents percent signs in OCI errors from being interpreted again.
	r.EventRecorder.Eventf(regarding, related, eventType, reason, action, "%s", truncateMessage(message, maxEventMessageBytes))
}

type boundedMessageError struct {
	err error
}

func (e boundedMessageError) Error() string {
	return truncateMessage(e.err.Error(), maxErrorMessageBytes)
}

func (e boundedMessageError) Unwrap() error { return e.err }

func reportControllerError(ctx context.Context, err error, operation string) error {
	if err == nil {
		return nil
	}
	var pending signer.PendingError
	if errors.As(err, &pending) {
		ctrl.LoggerFrom(ctx).Info(operation, "pending", true, "error", err.Error())
	} else {
		ctrl.LoggerFrom(ctx).Error(err, operation)
	}
	if len(err.Error()) <= maxErrorMessageBytes {
		return err
	}
	// issuer-lib forwards IssuerError.Err to the issuer controller separately.
	var issuerErr signer.IssuerError
	if errors.As(err, &issuerErr) {
		return signer.IssuerError{Err: boundedMessageError{err: issuerErr.Err}}
	}
	return boundedMessageError{err: err}
}
