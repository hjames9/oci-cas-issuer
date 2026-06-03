package v1alpha1

import (
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type AuthType string

const (
	AuthTypeWorkloadIdentity  AuthType = "workloadIdentity"
	AuthTypeInstancePrincipal AuthType = "instancePrincipal"
	AuthTypeAPIKey            AuthType = "apiKey"
)

type SecretKeySelector struct {
	Name string `json:"name"`
}

type OCIAuth struct {
	// +kubebuilder:default=workloadIdentity
	// +kubebuilder:validation:Enum=workloadIdentity;instancePrincipal;apiKey
	Type AuthType `json:"type,omitempty"`

	// Secret fields for apiKey auth: tenancy, user, region, fingerprint,
	// privateKey, and optionally passphrase.
	// +optional
	APIKeySecretRef *SecretKeySelector `json:"apiKeySecretRef,omitempty"`
}

type IssuerSpec struct {
	// +kubebuilder:validation:MinLength=1
	CertificateAuthorityID string `json:"certificateAuthorityId"`

	// +kubebuilder:validation:MinLength=1
	CompartmentID string `json:"compartmentId"`

	// +kubebuilder:validation:MinLength=1
	Region string `json:"region"`

	// +optional
	Auth OCIAuth `json:"auth,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"
// +kubebuilder:printcolumn:name="Reason",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].reason"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
type OCIIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IssuerSpec             `json:"spec,omitempty"`
	Status issuerapi.IssuerStatus `json:"status,omitempty"`
}

func (i *OCIIssuer) GetConditions() []metav1.Condition {
	return i.Status.Conditions
}

func (i *OCIIssuer) GetIssuerTypeIdentifier() string {
	return "ociissuers." + GroupName
}

var _ issuerapi.Issuer = &OCIIssuer{}

// +kubebuilder:object:root=true
type OCIIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OCIIssuer `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"
// +kubebuilder:printcolumn:name="Reason",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].reason"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
type OCIClusterIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IssuerSpec             `json:"spec,omitempty"`
	Status issuerapi.IssuerStatus `json:"status,omitempty"`
}

func (i *OCIClusterIssuer) GetConditions() []metav1.Condition {
	return i.Status.Conditions
}

func (i *OCIClusterIssuer) GetIssuerTypeIdentifier() string {
	return "ociclusterissuers." + GroupName
}

var _ issuerapi.Issuer = &OCIClusterIssuer{}

// +kubebuilder:object:root=true
type OCIClusterIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OCIClusterIssuer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OCIIssuer{}, &OCIIssuerList{}, &OCIClusterIssuer{}, &OCIClusterIssuerList{})
}
