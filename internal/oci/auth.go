package oci

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	casv1alpha1 "github.com/oci-cert-manager/oci-cas-issuer/api/v1alpha1"
)

type ConfigProviderFactory struct {
	Client                    client.Client
	ClusterResourceNamespace  string
	WorkloadIdentityProvider  func(region string) (common.ConfigurationProvider, error)
	InstancePrincipalProvider func() (common.ConfigurationProvider, error)
}

var (
	workloadIdentityEnvMu sync.Mutex

	defaultWorkloadIdentityProvider = func(region string) (common.ConfigurationProvider, error) {
		return withWorkloadIdentityEnv(region, func() (common.ConfigurationProvider, error) {
			return auth.OkeWorkloadIdentityConfigurationProvider()
		})
	}
	defaultInstancePrincipalProvider = func() (common.ConfigurationProvider, error) {
		return auth.InstancePrincipalConfigurationProvider()
	}
)

func (f ConfigProviderFactory) Provider(ctx context.Context, namespace string, spec casv1alpha1.IssuerSpec) (common.ConfigurationProvider, error) {
	authType := spec.Auth.Type
	if authType == "" {
		authType = casv1alpha1.AuthTypeWorkloadIdentity
	}

	switch authType {
	case casv1alpha1.AuthTypeWorkloadIdentity:
		provider, err := f.workloadIdentityProvider()(spec.Region)
		if err != nil {
			return nil, fmt.Errorf("build OKE workload identity provider: %w", err)
		}
		return provider, nil
	case casv1alpha1.AuthTypeInstancePrincipal:
		provider, err := f.instancePrincipalProvider()()
		if err != nil {
			return nil, fmt.Errorf("build instance principal provider: %w", err)
		}
		return provider, nil
	case casv1alpha1.AuthTypeAPIKey:
		if spec.Auth.APIKeySecretRef == nil || spec.Auth.APIKeySecretRef.Name == "" {
			return nil, fmt.Errorf("apiKey auth requires apiKeySecretRef.name")
		}
		var secret corev1.Secret
		if err := f.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: spec.Auth.APIKeySecretRef.Name}, &secret); err != nil {
			return nil, fmt.Errorf("get api key secret: %w", err)
		}
		return apiKeyProvider(secret.Data, spec.Region)
	default:
		return nil, fmt.Errorf("unsupported auth type %q", authType)
	}
}

func (f ConfigProviderFactory) workloadIdentityProvider() func(region string) (common.ConfigurationProvider, error) {
	if f.WorkloadIdentityProvider != nil {
		return f.WorkloadIdentityProvider
	}
	return defaultWorkloadIdentityProvider
}

func (f ConfigProviderFactory) instancePrincipalProvider() func() (common.ConfigurationProvider, error) {
	if f.InstancePrincipalProvider != nil {
		return f.InstancePrincipalProvider
	}
	return defaultInstancePrincipalProvider
}

func withWorkloadIdentityEnv(region string, build func() (common.ConfigurationProvider, error)) (common.ConfigurationProvider, error) {
	workloadIdentityEnvMu.Lock()
	defer workloadIdentityEnvMu.Unlock()

	restoreVersion := setEnvDefault(auth.ResourcePrincipalVersionEnvVar, auth.ResourcePrincipalVersion2_2)
	defer restoreVersion()
	restoreRegion := setEnvDefault(auth.ResourcePrincipalRegionEnvVar, region)
	defer restoreRegion()

	return build()
}

func setEnvDefault(key, value string) func() {
	previous, ok := os.LookupEnv(key)
	if !ok && value != "" {
		_ = os.Setenv(key, value)
	}
	return func() {
		if ok {
			_ = os.Setenv(key, previous)
			return
		}
		_ = os.Unsetenv(key)
	}
}

func apiKeyProvider(data map[string][]byte, fallbackRegion string) (common.ConfigurationProvider, error) {
	values := apiKeyValuesFromFields(data)
	if len(values) == 0 {
		var err error
		values, err = apiKeyValuesFromConfig(data)
		if err != nil {
			return nil, err
		}
	}
	region := values["region"]
	if region == "" {
		region = fallbackRegion
	}
	passphrase := string(data["passphrase"])
	if _, err := common.PrivateKeyFromBytesWithPassword([]byte(values["privateKey"]), []byte(passphrase)); err != nil {
		return nil, fmt.Errorf("parse api key private key: %w", err)
	}
	return common.NewRawConfigurationProvider(values["tenancy"], values["user"], region, values["fingerprint"], values["privateKey"], &passphrase), nil
}

func apiKeyValuesFromFields(data map[string][]byte) map[string]string {
	required := []string{"tenancy", "user", "fingerprint", "privateKey"}
	values := map[string]string{}
	for _, key := range required {
		raw := bytes.TrimSpace(data[key])
		if len(raw) == 0 {
			return nil
		}
		values[key] = string(raw)
	}
	values["region"] = string(bytes.TrimSpace(data["region"]))
	return values
}

func apiKeyValuesFromConfig(data map[string][]byte) (map[string]string, error) {
	config := parseOCIConfig(data["config"])
	values := map[string]string{
		"tenancy":     config["tenancy"],
		"user":        config["user"],
		"fingerprint": config["fingerprint"],
		"region":      config["region"],
		"privateKey":  normalizePEM(string(bytes.TrimSpace(data["key.pem"]))),
	}
	for _, key := range []string{"tenancy", "user", "fingerprint", "privateKey"} {
		if values[key] == "" {
			return nil, fmt.Errorf("api key secret missing %q", key)
		}
	}
	return values, nil
}

func parseOCIConfig(raw []byte) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return values
}

func normalizePEM(value string) string {
	end := "-----END "
	index := strings.Index(value, end)
	if index == -1 {
		return value
	}
	searchStart := index + len(end)
	lineEnd := strings.Index(value[searchStart:], "-----")
	if lineEnd == -1 {
		return value
	}
	lineEnd += searchStart + len("-----")
	return strings.TrimSpace(value[:lineEnd])
}
