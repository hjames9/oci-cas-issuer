package chart_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/yaml"
)

func TestDeployment(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm is required; make helm-test runs these checks with Helm installed")
	}
	chartData, err := os.ReadFile("../Chart.yaml")
	require.NoError(t, err)
	var chart struct {
		AppVersion string `json:"appVersion"`
	}
	require.NoError(t, yaml.NewYAMLOrJSONDecoder(bytes.NewReader(chartData), 4096).Decode(&chart))
	defaultFlags := []string{
		"--leader-elect",
		"--leader-elect-lease-duration=60s",
		"--leader-elect-renew-deadline=40s",
		"--leader-elect-retry-period=15s",
	}
	for _, tc := range []struct {
		name     string
		values   string
		flags    []string
		strategy appsv1.DeploymentStrategy
		imageTag string
	}{
		{name: "default object", flags: defaultFlags},
		{name: "explicit image tag", values: "image:\n  tag: custom-controller\n", flags: defaultFlags, imageTag: "custom-controller"},
		{name: "legacy true", values: "leaderElection: true\n", flags: defaultFlags},
		{name: "legacy false", values: "leaderElection: false\n"},
		{name: "disabled object", values: "leaderElection:\n  enabled: false\n"},
		{
			name:   "custom timings",
			values: "leaderElection:\n  enabled: true\n  leaseDuration: 90s\n  renewDeadline: 60s\n  retryPeriod: 20s\n",
			flags:  []string{"--leader-elect", "--leader-elect-lease-duration=90s", "--leader-elect-renew-deadline=60s", "--leader-elect-retry-period=20s"},
		},
		{
			name:   "partial object",
			values: "leaderElection:\n  renewDeadline: 35s\n",
			flags:  []string{"--leader-elect", "--leader-elect-lease-duration=60s", "--leader-elect-renew-deadline=35s", "--leader-elect-retry-period=15s"},
		},
		{
			name:     "recreate without election",
			values:   "leaderElection: false\nstrategy:\n  type: Recreate\n",
			strategy: appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType},
		},
		{
			name:   "custom rolling update",
			values: "strategy:\n  type: RollingUpdate\n  rollingUpdate:\n    maxSurge: 2\n    maxUnavailable: 0\n",
			flags:  defaultFlags,
			strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxSurge:       intstrPtr(2),
					MaxUnavailable: intstrPtr(0),
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			valuesPath := filepath.Join(t.TempDir(), "values.yaml")
			require.NoError(t, os.WriteFile(valuesPath, []byte(tc.values), 0600))
			cmd := exec.Command(helm, "template", "test", "..", "--namespace", "issuer-system", "--show-only", "templates/deployment.yaml", "--values", valuesPath)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			output, err := cmd.Output()
			require.NoError(t, err, "%s", stderr.String())
			var deployment appsv1.Deployment
			require.NoError(t, yaml.NewYAMLOrJSONDecoder(bytes.NewReader(output), 4096).Decode(&deployment))
			tag := chart.AppVersion + "-controller"
			if tc.imageTag != "" {
				tag = tc.imageTag
			}
			require.Equal(t, "ghcr.io/hjames9/oci-cas-issuer:"+tag, deployment.Spec.Template.Spec.Containers[0].Image)
			require.Equal(t, tc.strategy, deployment.Spec.Strategy)
			var flags []string
			for _, arg := range deployment.Spec.Template.Spec.Containers[0].Args {
				if strings.HasPrefix(arg, "--leader-elect") {
					flags = append(flags, arg)
				}
			}
			require.Equal(t, tc.flags, flags)
		})
	}
}

func intstrPtr(value int) *intstr.IntOrString {
	result := intstr.FromInt(value)
	return &result
}
