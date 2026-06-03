package oci

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	casv1alpha1 "github.com/oci-cert-manager/oci-cas-issuer/api/v1alpha1"
)

func TestAPIKeyProviderRequiresSecretFields(t *testing.T) {
	_, err := apiKeyProvider(map[string][]byte{"tenancy": []byte("t")}, "us-ashburn-1")
	require.ErrorContains(t, err, `api key secret missing "tenancy"`)
}

func TestAPIKeyProviderBuildsProvider(t *testing.T) {
	provider, err := apiKeyProvider(map[string][]byte{
		"tenancy":     []byte("ocid1.tenancy.oc1..aaaa"),
		"user":        []byte("ocid1.user.oc1..aaaa"),
		"fingerprint": []byte("aa:bb:cc"),
		"privateKey":  []byte("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"),
	}, "us-ashburn-1")
	require.NoError(t, err)
	region, err := provider.Region()
	require.NoError(t, err)
	require.Equal(t, "us-ashburn-1", region)
}

func TestAPIKeyProviderBuildsProviderFromOCIConfigSecret(t *testing.T) {
	provider, err := apiKeyProvider(map[string][]byte{
		"config": []byte(`[DEFAULT]
user=ocid1.user.oc1..aaaa
fingerprint=aa:bb:cc
tenancy=ocid1.tenancy.oc1..aaaa
region=us-phoenix-1
key_file=/etc/oci/key.pem
`),
		"key.pem": []byte("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nOCI_API_KEY"),
	}, "us-ashburn-1")
	require.NoError(t, err)
	region, err := provider.Region()
	require.NoError(t, err)
	require.Equal(t, "us-phoenix-1", region)
}

func TestAPIKeyProviderConfigSecretFallsBackToIssuerRegion(t *testing.T) {
	provider, err := apiKeyProvider(map[string][]byte{
		"config": []byte(`[DEFAULT]
user=ocid1.user.oc1..aaaa
fingerprint=aa:bb:cc
tenancy=ocid1.tenancy.oc1..aaaa
`),
		"key.pem": []byte("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"),
	}, "us-ashburn-1")
	require.NoError(t, err)
	region, err := provider.Region()
	require.NoError(t, err)
	require.Equal(t, "us-ashburn-1", region)
}

func TestParseOCIConfig(t *testing.T) {
	values := parseOCIConfig([]byte(`
# comment
[DEFAULT]
user = ocid1.user.oc1..aaaa
fingerprint= aa:bb:cc
`))
	require.Equal(t, "ocid1.user.oc1..aaaa", values["user"])
	require.Equal(t, "aa:bb:cc", values["fingerprint"])
}

func TestNormalizePEMWithoutEndMarker(t *testing.T) {
	require.Equal(t, "not-pem", normalizePEM("not-pem"))
}

func TestNormalizePEMWithMalformedEndMarker(t *testing.T) {
	value := "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY"
	require.Equal(t, value, normalizePEM(value))
}

func TestConfigProviderFactoryAPIKey(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "oci-api-key", Namespace: "default"},
		Data: map[string][]byte{
			"tenancy":     []byte("ocid1.tenancy.oc1..aaaa"),
			"user":        []byte("ocid1.user.oc1..aaaa"),
			"fingerprint": []byte("aa:bb:cc"),
			"privateKey":  []byte("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"),
			"region":      []byte("us-phoenix-1"),
		},
	}
	factory := ConfigProviderFactory{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()}

	provider, err := factory.Provider(context.Background(), "default", casv1alpha1.IssuerSpec{
		Region: "us-ashburn-1",
		Auth: casv1alpha1.OCIAuth{
			Type:            casv1alpha1.AuthTypeAPIKey,
			APIKeySecretRef: &casv1alpha1.SecretKeySelector{Name: "oci-api-key"},
		},
	})
	require.NoError(t, err)
	region, err := provider.Region()
	require.NoError(t, err)
	require.Equal(t, "us-phoenix-1", region)
}

func TestConfigProviderFactoryErrors(t *testing.T) {
	factory := ConfigProviderFactory{Client: fake.NewClientBuilder().Build()}
	_, err := factory.Provider(context.Background(), "default", casv1alpha1.IssuerSpec{
		Auth: casv1alpha1.OCIAuth{Type: casv1alpha1.AuthTypeAPIKey},
	})
	require.ErrorContains(t, err, "apiKeySecretRef.name")

	_, err = factory.Provider(context.Background(), "default", casv1alpha1.IssuerSpec{
		Auth: casv1alpha1.OCIAuth{
			Type:            casv1alpha1.AuthTypeAPIKey,
			APIKeySecretRef: &casv1alpha1.SecretKeySelector{Name: "missing"},
		},
	})
	require.ErrorContains(t, err, "get api key secret")

	_, err = factory.Provider(context.Background(), "default", casv1alpha1.IssuerSpec{
		Auth: casv1alpha1.OCIAuth{Type: casv1alpha1.AuthType("unknown")},
	})
	require.ErrorContains(t, err, "unsupported auth type")
}

func TestConfigProviderFactoryWorkloadIdentityAndInstancePrincipal(t *testing.T) {
	raw := common.NewRawConfigurationProvider("tenancy", "user", "us-ashburn-1", "fingerprint", "key", nil)
	factory := ConfigProviderFactory{
		WorkloadIdentityProvider: func(region string) (common.ConfigurationProvider, error) {
			require.Empty(t, region)
			return raw, nil
		},
		InstancePrincipalProvider: func() (common.ConfigurationProvider, error) {
			return raw, nil
		},
	}

	provider, err := factory.Provider(context.Background(), "default", casv1alpha1.IssuerSpec{})
	require.NoError(t, err)
	region, err := provider.Region()
	require.NoError(t, err)
	require.Equal(t, "us-ashburn-1", region)

	provider, err = factory.Provider(context.Background(), "default", casv1alpha1.IssuerSpec{
		Auth: casv1alpha1.OCIAuth{Type: casv1alpha1.AuthTypeInstancePrincipal},
	})
	require.NoError(t, err)
	region, err = provider.Region()
	require.NoError(t, err)
	require.Equal(t, "us-ashburn-1", region)
}

func TestConfigProviderFactoryPrincipalErrors(t *testing.T) {
	factory := ConfigProviderFactory{
		WorkloadIdentityProvider: func(string) (common.ConfigurationProvider, error) {
			return nil, errors.New("workload")
		},
		InstancePrincipalProvider: func() (common.ConfigurationProvider, error) {
			return nil, errors.New("instance")
		},
	}
	_, err := factory.Provider(context.Background(), "default", casv1alpha1.IssuerSpec{})
	require.ErrorContains(t, err, "workload")

	_, err = factory.Provider(context.Background(), "default", casv1alpha1.IssuerSpec{
		Auth: casv1alpha1.OCIAuth{Type: casv1alpha1.AuthTypeInstancePrincipal},
	})
	require.ErrorContains(t, err, "instance")
}

func TestConfigProviderFactoryDefaultPrincipalBuilders(t *testing.T) {
	require.NotNil(t, (ConfigProviderFactory{}).workloadIdentityProvider())
	require.NotNil(t, (ConfigProviderFactory{}).instancePrincipalProvider())

	raw := common.NewRawConfigurationProvider("tenancy", "user", "region", "fingerprint", "key", nil)
	provider, err := ConfigProviderFactory{
		WorkloadIdentityProvider: func(region string) (common.ConfigurationProvider, error) {
			require.Empty(t, region)
			return raw, nil
		},
	}.workloadIdentityProvider()("")
	require.NoError(t, err)
	region, err := provider.Region()
	require.NoError(t, err)
	require.Equal(t, "region", region)
	provider, err = ConfigProviderFactory{
		InstancePrincipalProvider: func() (common.ConfigurationProvider, error) { return raw, nil },
	}.instancePrincipalProvider()()
	require.NoError(t, err)
	region, err = provider.Region()
	require.NoError(t, err)
	require.Equal(t, "region", region)
}

func TestWithWorkloadIdentityEnvDefaultsMissingValues(t *testing.T) {
	t.Setenv(auth.ResourcePrincipalVersionEnvVar, "")
	t.Setenv(auth.ResourcePrincipalRegionEnvVar, "")
	require.NoError(t, os.Unsetenv(auth.ResourcePrincipalVersionEnvVar))
	require.NoError(t, os.Unsetenv(auth.ResourcePrincipalRegionEnvVar))
	raw := common.NewRawConfigurationProvider("tenancy", "user", "us-ashburn-1", "fingerprint", "key", nil)

	provider, err := withWorkloadIdentityEnv("us-ashburn-1", func() (common.ConfigurationProvider, error) {
		require.Equal(t, auth.ResourcePrincipalVersion2_2, os.Getenv(auth.ResourcePrincipalVersionEnvVar))
		require.Equal(t, "us-ashburn-1", os.Getenv(auth.ResourcePrincipalRegionEnvVar))
		return raw, nil
	})

	require.NoError(t, err)
	require.Equal(t, raw, provider)
	_, ok := os.LookupEnv(auth.ResourcePrincipalVersionEnvVar)
	require.False(t, ok)
	_, ok = os.LookupEnv(auth.ResourcePrincipalRegionEnvVar)
	require.False(t, ok)
}

func TestWithWorkloadIdentityEnvPreservesExistingValues(t *testing.T) {
	t.Setenv(auth.ResourcePrincipalVersionEnvVar, auth.ResourcePrincipalVersion1_1)
	t.Setenv(auth.ResourcePrincipalRegionEnvVar, "us-phoenix-1")

	_, err := withWorkloadIdentityEnv("us-ashburn-1", func() (common.ConfigurationProvider, error) {
		require.Equal(t, auth.ResourcePrincipalVersion1_1, os.Getenv(auth.ResourcePrincipalVersionEnvVar))
		require.Equal(t, "us-phoenix-1", os.Getenv(auth.ResourcePrincipalRegionEnvVar))
		return nil, errors.New("stop")
	})

	require.ErrorContains(t, err, "stop")
	require.Equal(t, auth.ResourcePrincipalVersion1_1, os.Getenv(auth.ResourcePrincipalVersionEnvVar))
	require.Equal(t, "us-phoenix-1", os.Getenv(auth.ResourcePrincipalRegionEnvVar))
}
