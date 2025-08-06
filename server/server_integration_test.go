// SPDX-License-Identifier: Apache-2.0
//go:build integration
// +build integration

package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"
	"github.com/oscal-compass/oscal-sdk-go/extensions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Integration tests that run against a live Kubernetes cluster
// Run with: go test -tags=integration ./server

// getTestKubeconfig returns the path to kubeconfig for testing
// It follows the same logic as server's getKubeconfigPath
func getTestKubeconfig(t *testing.T) string {
	// Check KUBECONFIG environment variable first
	if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
		if _, err := os.Stat(kubeconfig); err == nil {
			return kubeconfig
		}
		t.Logf("KUBECONFIG env var set to %s but file not found", kubeconfig)
	}

	// Check default location
	home, err := os.UserHomeDir()
	if err == nil {
		kubeconfigPath := filepath.Join(home, ".kube", "config")
		if _, err := os.Stat(kubeconfigPath); err == nil {
			return kubeconfigPath
		}
	}

	return ""
}

func TestPluginServer_KubernetesIntegration(t *testing.T) {
	// Skip if no kubeconfig is available
	kubeconfigPath := getTestKubeconfig(t)
	if kubeconfigPath == "" {
		t.Skip("No kubeconfig found - set KUBECONFIG env var or ensure ~/.kube/config exists")
	}
	// Setup test workspace
	workspace := setupTestWorkspace(t)

	s := New()
	err := s.Configure(context.Background(), map[string]string{
		"workspace":          workspace,
		"enable_kubernetes":  "true",
		"enable_filesystem":  "false",
		"target_name":        "integration-test-cluster",
		"target_type":        "kubernetes-cluster",
		"target_id":          "test-cluster-001",
		"include_namespaces": "default,kube-system",
	})
	require.NoError(t, err)

	// Verify Kubernetes clients were initialized
	assert.NotNil(t, s.clientset)
	assert.NotNil(t, s.runtimeClient)

	// Test connectivity
	_, err = s.clientset.CoreV1().Namespaces().Get(context.Background(), "default", metav1.GetOptions{})
	require.NoError(t, err, "Failed to connect to Kubernetes cluster")
}

func TestPluginServer_GenerateAndScanKubernetes(t *testing.T) {
	// Skip if no cluster access
	if os.Getenv("SKIP_K8S_TESTS") != "" {
		t.Skip("SKIP_K8S_TESTS is set")
	}

	kubeconfigPath := os.Getenv("KUBECONFIG")
	if kubeconfigPath == "" {
		home, _ := os.UserHomeDir()
		kubeconfigPath = filepath.Join(home, ".kube", "config")
	}

	if _, err := os.Stat(kubeconfigPath); os.IsNotExist(err) {
		t.Skip("No kubeconfig found")
	}

	workspace := setupTestWorkspace(t)

	s := New()
	err := s.Configure(context.Background(), map[string]string{
		"workspace":          workspace,
		"enable_kubernetes":  "true",
		"target_name":        "test-k8s-cluster",
		"target_type":        "kubernetes-cluster",
		"include_namespaces": "default",
	})
	require.NoError(t, err)

	// Create test policy with Kubernetes-specific rules
	testPolicy := policy.Policy{
		{
			Rule: extensions.Rule{
				ID:          "k8s-pod-security",
				Description: "Kubernetes pod security checks",
			},
			Checks: []extensions.Check{
				{
					ID:          "pod-security-context",
					Description: "Ensure pods have security context",
				},
			},
		},
		{
			Rule: extensions.Rule{
				ID:          "k8s-resource-limits",
				Description: "Kubernetes resource management",
			},
			Checks: []extensions.Check{
				{
					ID:          "resource-limits",
					Description: "Ensure containers have resource limits",
				},
			},
		},
	}

	// Generate rules
	err = s.Generate(context.Background(), testPolicy)
	require.NoError(t, err)

	// Verify rules were generated
	rulesFile := filepath.Join(workspace, "celscanner", "policy", "cel-rules.yaml")
	assert.FileExists(t, rulesFile)

	// Check if file exists and print contents
	rulesFileContent, _ := os.ReadFile(rulesFile)
	t.Logf("Rules file content: %s", string(rulesFileContent))

	// Run scan
	results, err := s.GetResults(context.Background(), testPolicy)
	require.NoError(t, err)

	// Log results for debugging
	t.Logf("Scan results: %+v", results)

	// Should have results for our checks
	assert.NotEmpty(t, results.ObservationsByCheck)

	// Verify results file was created
	resultsFile := filepath.Join(workspace, "celscanner", "results", "cel-results.yaml")
	assert.FileExists(t, resultsFile)
}

func TestPluginServer_CustomMappingIntegration(t *testing.T) {
	// Setup test workspace
	workspace := setupTestWorkspace(t)

	// Create custom mapping file
	mappingFile := filepath.Join(workspace, "custom-mappings.yaml")
	mappingContent := `
mappings:
  namespace-labels:
    expression: "resource.metadata.labels['environment'] in ['prod', 'staging', 'dev']"
    description: "Check namespace has environment label"
    inputs:
      - name: resource
        type: kubernetes
        resource: namespaces
  deployment-replicas:
    expression: "resource.spec.replicas >= 2"
    description: "Check deployment has at least 2 replicas"
    inputs:
      - name: resource
        type: kubernetes
        resource: deployments
`
	err := os.WriteFile(mappingFile, []byte(mappingContent), 0644)
	require.NoError(t, err)

	s := New()
	err = s.Configure(context.Background(), map[string]string{
		"workspace":          workspace,
		"enable_kubernetes":  "true",
		"mapping_file":       mappingFile,
		"include_namespaces": "default",
	})
	require.NoError(t, err)

	// Test policy using custom mappings
	testPolicy := policy.Policy{
		{
			Rule: extensions.Rule{
				ID:          "custom-k8s-checks",
				Description: "Custom Kubernetes checks",
			},
			Checks: []extensions.Check{
				{
					ID:          "namespace-labels",
					Description: "Custom namespace label check",
				},
				{
					ID:          "deployment-replicas",
					Description: "Custom deployment replica check",
				},
			},
		},
	}

	err = s.Generate(context.Background(), testPolicy)
	require.NoError(t, err)

	// Verify custom expressions were used
	rulesFile := filepath.Join(workspace, "celscanner", "policy", "cel-rules.yaml")
	data, err := os.ReadFile(rulesFile)
	require.NoError(t, err)

	var rules []map[string]interface{}
	err = yaml.Unmarshal(data, &rules)
	require.NoError(t, err)

	// Should have mapped both custom checks
	assert.Len(t, rules, 2)
}

func TestPluginServer_LiveClusterScanning(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping live cluster test in short mode")
	}

	// Use kubeconfig from environment or default path
	kubeconfigPath := getTestKubeconfig(t)
	if kubeconfigPath == "" {
		t.Skip("No kubeconfig found - set KUBECONFIG env var or ensure ~/.kube/config exists")
	}

	// Set KUBECONFIG env var for this test if not already set
	oldKubeconfig := os.Getenv("KUBECONFIG")
	if oldKubeconfig == "" {
		os.Setenv("KUBECONFIG", kubeconfigPath)
		defer os.Unsetenv("KUBECONFIG")
	}

	workspace := setupTestWorkspace(t)

	s := New()
	err := s.Configure(context.Background(), map[string]string{
		"workspace":          workspace,
		"enable_kubernetes":  "true",
		"target_name":        "live-test-cluster",
		"target_type":        "kubernetes-cluster",
		"include_namespaces": "default,kube-system",
	})
	require.NoError(t, err)

	// Create a comprehensive test policy
	testPolicy := policy.Policy{
		{
			Rule: extensions.Rule{
				ID:          "pod-security-standards",
				Description: "Pod Security Standards compliance",
			},
			Checks: []extensions.Check{
				{
					ID:          "pod-security-context",
					Description: "Pods must have security context",
				},
				{
					ID:          "privileged-containers",
					Description: "No privileged containers allowed",
				},
			},
		},
		{
			Rule: extensions.Rule{
				ID:          "resource-management",
				Description: "Resource limits and requests",
			},
			Checks: []extensions.Check{
				{
					ID:          "resource-limits",
					Description: "Containers must have resource limits",
				},
			},
		},
	}

	// Generate rules
	err = s.Generate(context.Background(), testPolicy)
	require.NoError(t, err)

	// Run scan with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	results, err := s.GetResults(ctx, testPolicy)
	require.NoError(t, err)

	// Log results for debugging
	for _, obs := range results.ObservationsByCheck {
		t.Logf("Check: %s", obs.CheckID)
		for _, subject := range obs.Subjects {
			t.Logf("  Subject: %s (%s) - Result: %v",
				subject.Title, subject.Type, subject.Result)
		}
	}

	// Should have observations for each check
	assert.GreaterOrEqual(t, len(results.ObservationsByCheck), 1)

	// Verify results were saved
	resultsFile := filepath.Join(workspace, "celscanner", "results", "cel-results.yaml")
	resultsData, err := os.ReadFile(resultsFile)
	require.NoError(t, err)
	assert.NotEmpty(t, resultsData)
}

// TestClusterConnectivity verifies we can connect to the cluster
func TestClusterConnectivity(t *testing.T) {
	s := New()

	// Try to setup Kubernetes clients
	err := s.setupKubernetesClients()
	if err != nil {
		t.Skipf("Cannot connect to Kubernetes cluster: %v", err)
	}

	// Test basic API access
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// List namespaces
	namespaces, err := s.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	assert.NotEmpty(t, namespaces.Items)

	t.Logf("Connected to cluster with %d namespaces", len(namespaces.Items))

	// Check if we can access pods in default namespace
	pods, err := s.clientset.CoreV1().Pods("default").List(ctx, metav1.ListOptions{})
	if err != nil && !errors.IsNotFound(err) && !errors.IsForbidden(err) {
		t.Errorf("Unexpected error listing pods: %v", err)
	}

	if err == nil {
		t.Logf("Found %d pods in default namespace", len(pods.Items))
	}
}
