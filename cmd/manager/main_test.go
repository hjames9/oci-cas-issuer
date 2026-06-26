package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInClusterNamespaceOutsideCluster(t *testing.T) {
	namespace, err := inClusterNamespace()
	if err == nil {
		require.NotEmpty(t, namespace)
		return
	}
	require.True(t, errors.Is(err, errNotInCluster) || namespace == "")
}

func TestNamespaceFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "namespace")
	require.NoError(t, os.WriteFile(path, []byte("oci-cas-issuer"), 0600))

	namespace, err := namespaceFromFile(path)
	require.NoError(t, err)
	require.Equal(t, "oci-cas-issuer", namespace)

	namespace, err = namespaceFromFile(filepath.Join(t.TempDir(), "missing"))
	require.ErrorIs(t, err, errNotInCluster)
	require.Empty(t, namespace)

	namespace, err = namespaceFromFile(t.TempDir())
	require.ErrorContains(t, err, "read namespace")
	require.Empty(t, namespace)
}
