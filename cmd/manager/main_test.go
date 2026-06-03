package main

import (
	"errors"
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
