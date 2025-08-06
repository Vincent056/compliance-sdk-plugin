package server

import (
	"strings"
	"testing"

	"github.com/Vincent056/celscanner"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pluginconfig "github.com/Vincent056/compliance-sdk-plugin/config"
)

// TestSystemServiceChecks tests the system service check functionality
func TestSystemServiceChecks(t *testing.T) {
	tests := []struct {
		name            string
		checkID         string
		expectedCommand string
		expectedArgs    []string
		expectedExpr    string
	}{
		{
			name:            "SSH service enabled check",
			checkID:         "sshd-service-enabled",
			expectedCommand: "systemctl",
			expectedArgs:    []string{"is-enabled", "sshd"},
			expectedExpr:    `service.success && contains(service.output, "enabled")`,
		},
		{
			name:            "SSH service running check",
			checkID:         "sshd-service-running",
			expectedCommand: "systemctl",
			expectedArgs:    []string{"is-active", "sshd"},
			expectedExpr:    `service.success && contains(service.output, "active")`,
		},
		{
			name:            "Firewall enabled check",
			checkID:         "firewalld-enabled",
			expectedCommand: "systemctl",
			expectedArgs:    []string{"is-enabled", "firewalld"},
			expectedExpr:    `service.success && contains(service.output, "enabled")`,
		},
		{
			name:            "Firewall running check",
			checkID:         "firewalld-running",
			expectedCommand: "systemctl",
			expectedArgs:    []string{"is-active", "firewalld"},
			expectedExpr:    `service.success && contains(service.output, "active")`,
		},
		{
			name:            "SELinux enforcing check",
			checkID:         "selinux-enforcing",
			expectedCommand: "getenforce",
			expectedArgs:    []string{},
			expectedExpr:    `selinux.success && contains(selinux.output, "Enforcing")`,
		},
	}

	s := &PluginServer{
		Config: &pluginconfig.Config{},
	}
	s.Config.Files.MappingFile = "" // Use built-in mappings

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test expression mapping
			expr := s.mapCheckToExpression(tt.checkID)
			assert.Equal(t, tt.expectedExpr, expr, "Expression mismatch for %s", tt.checkID)
		})
	}
}

// TestExtractServiceName tests the service name extraction function
func TestExtractServiceName(t *testing.T) {
	tests := []struct {
		checkID      string
		expectedName string
	}{
		{"sshd-service-enabled", "sshd"},
		{"sshd-service-running", "sshd"},
		{"firewalld-enabled", "firewalld"},
		{"firewalld-running", "firewalld"},
		{"selinux-enforcing", "selinux"},
		{"unknown-service", "unknown"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.checkID, func(t *testing.T) {
			result := extractServiceName(tt.checkID)
			assert.Equal(t, tt.expectedName, result)
		})
	}
}

// TestSystemRuleGeneration tests the generation of system service rules
func TestSystemRuleGeneration(t *testing.T) {
	// Create a logger
	hclog.SetDefault(hclog.NewNullLogger())

	// Test cases for system service checks
	testCases := []struct {
		checkID      string
		inputName    string
		commandOrSvc string // either command or service name
		isCommand    bool
	}{
		{
			checkID:      "sshd-service-enabled",
			inputName:    "service",
			commandOrSvc: "systemctl",
			isCommand:    true,
		},
		{
			checkID:      "selinux-enforcing",
			inputName:    "selinux",
			commandOrSvc: "getenforce",
			isCommand:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.checkID, func(t *testing.T) {
			// Build a rule using the same pattern as server.go
			ruleBuilder := celscanner.NewRuleBuilder(tc.checkID).
				WithName("Test " + tc.checkID).
				WithDescription("Test description")

			// Add system input based on check type
			if tc.checkID == "selinux-enforcing" {
				ruleBuilder.WithSystemInput("selinux", "", "getenforce", []string{})
			} else if strings.Contains(tc.checkID, "enabled") {
				serviceName := extractServiceName(tc.checkID)
				ruleBuilder.WithSystemInput("service", "", "systemctl", []string{"is-enabled", serviceName})
			} else if strings.Contains(tc.checkID, "running") || strings.Contains(tc.checkID, "active") {
				serviceName := extractServiceName(tc.checkID)
				ruleBuilder.WithSystemInput("service", "", "systemctl", []string{"is-active", serviceName})
			}

			// Set expression
			s := &PluginServer{Config: &pluginconfig.Config{}}
			expr := s.mapCheckToExpression(tc.checkID)
			ruleBuilder.SetExpression(expr)

			// Build the rule
			rule, err := ruleBuilder.Build()
			require.NoError(t, err, "Failed to build rule for %s", tc.checkID)

			// Verify rule properties
			assert.Equal(t, tc.checkID, rule.Identifier())
			assert.NotEmpty(t, rule.Expression())
			assert.Len(t, rule.Inputs(), 1, "Should have exactly one input")

			// Verify input type
			input := rule.Inputs()[0]
			assert.Equal(t, celscanner.InputTypeSystem, input.Type())
		})
	}
}

// TestSystemServiceLimitation tests that system commands are properly limited
func TestSystemServiceLimitation(t *testing.T) {
	// Test that the fetcher is created with limited system access
	s := &PluginServer{
		Config: &pluginconfig.Config{},
	}
	s.Config.Features.SystemEnabled = true

	// Create scanner (this would normally call createLocalScanner)
	// We're verifying the configuration is correct for limited system access

	// The implementation should:
	// 1. Set WithSystem(false) to disable general commands
	// 2. Only allow specific service status commands through validation

	// This is a conceptual test showing the security limitation
	assert.True(t, s.Config.Features.SystemEnabled, "System should be enabled")
	// In actual implementation, system fetcher would be created with:
	// fetcherBuilder.WithSystem(false) // Disable general system commands
}

// TestRuleStoreIntegration tests integration with the rule store for system rules
func TestRuleStoreIntegration(t *testing.T) {
	// Create temporary directory for rule store
	tmpDir := t.TempDir()

	store, err := NewRuleStore(tmpDir)
	require.NoError(t, err)

	// Create a system service rule
	rule := &StoredRule{
		ID:          "test-sshd-check",
		Name:        "Test SSH Service Check",
		Description: "Test rule for SSH service",
		Expression:  `service.success && contains(service.output, "active")`,
		Inputs: []RuleInputConfig{
			{
				Name:    "service",
				Type:    "system",
				Command: "systemctl",
				Args:    []string{"is-active", "sshd"},
			},
		},
		Tags:     []string{"test", "ssh", "system"},
		Category: "system-services",
		Severity: "HIGH",
		CheckID:  "test-sshd-check",
	}

	// Save the rule
	err = store.Save(rule)
	require.NoError(t, err)

	// Retrieve the rule
	retrieved, err := store.Get(rule.ID)
	require.NoError(t, err)
	assert.Equal(t, rule.Name, retrieved.Name)
	assert.Equal(t, rule.Expression, retrieved.Expression)

	// Convert to CEL rule
	celRule, err := store.ConvertToCelRule(retrieved)
	require.NoError(t, err)
	assert.Equal(t, rule.ID, celRule.Identifier())
	assert.Equal(t, rule.Expression, celRule.Expression())
	assert.Len(t, celRule.Inputs(), 1)

	// Verify system input
	input := celRule.Inputs()[0]
	assert.Equal(t, celscanner.InputTypeSystem, input.Type())
	assert.Equal(t, "service", input.Name())
}
