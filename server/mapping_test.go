package server

import (
	"os"
	"testing"

	"github.com/Vincent056/celscanner"
	"github.com/hashicorp/go-hclog"
	"github.com/oscal-compass/oscal-sdk-go/extensions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pluginconfig "github.com/Vincent056/compliance-sdk-plugin/config"
)

func TestMappingConfig(t *testing.T) {
	// Test loading mapping configuration
	tests := []struct {
		name     string
		yaml     string
		expected MappingConfig
		wantErr  bool
	}{
		{
			name: "Valid mapping config",
			yaml: `
version: "1.0"
mappings:
  test-rule:
    type: stored_rules
    rule_ids:
      - rule1
      - rule2
    description: "Test mapping"
  inline-rule:
    type: inline
    rules:
      - id: test-inline
        expression: "true"
        inputs:
          - name: test
            type: file
            path: "/test"
parameters:
  namespace:
    default: "default"
    description: "Test namespace"
`,
			expected: MappingConfig{
				Version: "1.0",
				Mappings: map[string]MappingDefinition{
					"test-rule": {
						Type:        "stored_rules",
						RuleIDs:     []string{"rule1", "rule2"},
						Description: "Test mapping",
					},
					"inline-rule": {
						Type:        "inline",
						Description: "",
						Rules: []InlineCELRule{
							{
								ID:         "test-inline",
								Expression: "true",
								Inputs: []InputDef{
									{
										Name: "test",
										Type: "file",
										Path: "/test",
									},
								},
							},
						},
					},
				},
				Parameters: map[string]ParameterDef{
					"namespace": {
						Default:     "default",
						Description: "Test namespace",
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write test YAML to temp file
			tmpFile := t.TempDir() + "/mapping.yaml"
			err := os.WriteFile(tmpFile, []byte(tt.yaml), 0644)
			require.NoError(t, err)

			// Create server with config
			s := &PluginServer{
				Config: &pluginconfig.Config{},
			}
			s.Config.Files.MappingFile = tmpFile

			// Load mapping config
			config, err := s.loadMappingConfig()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected.Version, config.Version)
				assert.Equal(t, len(tt.expected.Mappings), len(config.Mappings))
			}
		})
	}
}

func TestGetCELRulesForRuleSet(t *testing.T) {
	// Setup logger
	hclog.SetDefault(hclog.NewNullLogger())

	// Create temp rule store
	tmpDir := t.TempDir()
	store, err := NewRuleStore(tmpDir)
	require.NoError(t, err)

	// Save a test rule
	testRule := &StoredRule{
		ID:         "test-stored-rule",
		Name:       "Test Stored Rule",
		Expression: `test.value == "expected"`,
		Inputs: []RuleInputConfig{
			{
				Name: "test",
				Type: "file",
				Path: "/test/path",
			},
		},
	}
	err = store.Save(testRule)
	require.NoError(t, err)

	// Create server with rule store
	s := &PluginServer{
		Config:    &pluginconfig.Config{},
		ruleStore: store,
	}

	// Test cases
	tests := []struct {
		name          string
		ruleSet       extensions.RuleSet
		mappingConfig *MappingConfig
		expectedCount int
		expectedIDs   []string
	}{
		{
			name: "Map RuleSet ID to stored rules",
			ruleSet: extensions.RuleSet{
				Rule: extensions.Rule{
					ID:          "test-ruleset",
					Description: "Test RuleSet",
				},
				Checks: []extensions.Check{},
			},
			mappingConfig: &MappingConfig{
				Mappings: map[string]MappingDefinition{
					"test-ruleset": {
						Type:    "stored_rules",
						RuleIDs: []string{"test-stored-rule"},
					},
				},
			},
			expectedCount: 1,
			expectedIDs:   []string{"test-stored-rule"},
		},
		{
			name: "Map to inline rules",
			ruleSet: extensions.RuleSet{
				Rule: extensions.Rule{
					ID:          "inline-test",
					Description: "Inline Test",
				},
			},
			mappingConfig: &MappingConfig{
				Mappings: map[string]MappingDefinition{
					"inline-test": {
						Type: "inline",
						Rules: []InlineCELRule{
							{
								ID:         "inline-1",
								Expression: "true",
								Inputs:     []InputDef{{Name: "test", Type: "file"}},
							},
							{
								ID:         "inline-2",
								Expression: "false",
								Inputs:     []InputDef{{Name: "test", Type: "file"}},
							},
						},
					},
				},
			},
			expectedCount: 2,
			expectedIDs:   []string{"inline-1", "inline-2"},
		},
		{
			name: "Fall back to built-in mappings",
			ruleSet: extensions.RuleSet{
				Rule: extensions.Rule{
					ID: "unmapped-rule",
				},
				Checks: []extensions.Check{
					{
						ID:          "sshd-service-enabled",
						Description: "SSH service enabled",
					},
				},
			},
			mappingConfig: nil,
			expectedCount: 1,
			expectedIDs:   []string{"sshd-service-enabled"},
		},
		{
			name: "Map Check IDs",
			ruleSet: extensions.RuleSet{
				Rule: extensions.Rule{
					ID: "check-based-rule",
				},
				Checks: []extensions.Check{
					{
						ID:          "mapped-check",
						Description: "Mapped check",
					},
				},
			},
			mappingConfig: &MappingConfig{
				Mappings: map[string]MappingDefinition{
					"mapped-check": {
						Type:    "stored_rules",
						RuleIDs: []string{"test-stored-rule"},
					},
				},
			},
			expectedCount: 1,
			expectedIDs:   []string{"test-stored-rule"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := s.getCELRulesForRuleSet(tt.ruleSet, tt.mappingConfig)
			assert.NoError(t, err)
			assert.Len(t, rules, tt.expectedCount)

			// Check rule IDs
			ruleIDs := make([]string, len(rules))
			for i, rule := range rules {
				ruleIDs[i] = rule.Identifier()
			}
			assert.ElementsMatch(t, tt.expectedIDs, ruleIDs)
		})
	}
}

func TestProcessMappingDefinition(t *testing.T) {
	// Setup
	hclog.SetDefault(hclog.NewNullLogger())
	tmpDir := t.TempDir()
	store, _ := NewRuleStore(tmpDir)

	// Save test rules
	rule1 := &StoredRule{
		ID:         "rule1",
		Name:       "Rule 1",
		Expression: "true",
		Inputs:     []RuleInputConfig{{Name: "test", Type: "file"}},
	}
	rule2 := &StoredRule{
		ID:         "rule2",
		Name:       "Rule 2",
		Expression: "false",
		Inputs:     []RuleInputConfig{{Name: "test", Type: "file"}},
	}
	store.Save(rule1)
	store.Save(rule2)

	s := &PluginServer{
		Config:    &pluginconfig.Config{},
		ruleStore: store,
	}

	ruleSet := extensions.RuleSet{
		Rule: extensions.Rule{
			ID:          "test-ruleset",
			Description: "Test",
		},
	}

	tests := []struct {
		name          string
		mapping       MappingDefinition
		expectedCount int
		wantErr       bool
	}{
		{
			name: "Process stored rules",
			mapping: MappingDefinition{
				Type:    "stored_rules",
				RuleIDs: []string{"rule1", "rule2"},
			},
			expectedCount: 2,
			wantErr:       false,
		},
		{
			name: "Process inline rules",
			mapping: MappingDefinition{
				Type: "inline",
				Rules: []InlineCELRule{
					{
						ID:         "inline1",
						Expression: "true",
						Inputs:     []InputDef{{Name: "test", Type: "file", Path: "/test"}},
					},
				},
			},
			expectedCount: 1,
			wantErr:       false,
		},
		{
			name: "Unknown mapping type",
			mapping: MappingDefinition{
				Type: "unknown",
			},
			expectedCount: 0,
			wantErr:       true,
		},
		{
			name: "Missing stored rule",
			mapping: MappingDefinition{
				Type:    "stored_rules",
				RuleIDs: []string{"nonexistent"},
			},
			expectedCount: 0,
			wantErr:       false, // Should not error, just warn
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := s.processMappingDefinition(ruleSet, tt.mapping)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, rules, tt.expectedCount)
			}
		})
	}
}

func TestCreateCELRuleFromInline(t *testing.T) {
	s := &PluginServer{Config: &pluginconfig.Config{}}

	ruleSet := extensions.RuleSet{
		Rule: extensions.Rule{
			ID:          "test-ruleset",
			Description: "Test RuleSet",
		},
	}

	tests := []struct {
		name        string
		inline      InlineCELRule
		expectError bool
		validate    func(t *testing.T, rule celscanner.CelRule)
	}{
		{
			name: "Kubernetes input",
			inline: InlineCELRule{
				ID:         "k8s-test",
				Expression: "resource.kind == 'Pod'",
				Inputs: []InputDef{
					{
						Name:      "resource",
						Type:      "kubernetes",
						Resource:  "pods",
						Namespace: "default",
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, rule celscanner.CelRule) {
				assert.Equal(t, "k8s-test", rule.Identifier())
				assert.Equal(t, "resource.kind == 'Pod'", rule.Expression())
				assert.Len(t, rule.Inputs(), 1)
				assert.Equal(t, celscanner.InputTypeKubernetes, rule.Inputs()[0].Type())
			},
		},
		{
			name: "System input",
			inline: InlineCELRule{
				ID:         "system-test",
				Expression: `service.success`,
				Inputs: []InputDef{
					{
						Name:    "service",
						Type:    "system",
						Command: "systemctl",
						Args:    []string{"is-active", "sshd"},
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, rule celscanner.CelRule) {
				assert.Equal(t, "system-test", rule.Identifier())
				assert.Len(t, rule.Inputs(), 1)
				assert.Equal(t, celscanner.InputTypeSystem, rule.Inputs()[0].Type())
			},
		},
		{
			name: "Multiple inputs",
			inline: InlineCELRule{
				ID:         "multi-input",
				Expression: "file.exists && http.status == 200",
				Inputs: []InputDef{
					{Name: "file", Type: "file", Path: "/test"},
					{Name: "http", Type: "http", URL: "http://test"},
				},
			},
			expectError: false,
			validate: func(t *testing.T, rule celscanner.CelRule) {
				assert.Len(t, rule.Inputs(), 2)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := s.createCELRuleFromInline(ruleSet, tt.inline)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, rule)
				}
			}
		})
	}
}

func TestAddDefaultInputs(t *testing.T) {
	s := &PluginServer{Config: &pluginconfig.Config{}}

	tests := []struct {
		checkID      string
		validateFunc func(t *testing.T, builder *celscanner.RuleBuilder)
	}{
		{
			checkID: "pod-security-context",
			validateFunc: func(t *testing.T, builder *celscanner.RuleBuilder) {
				// Would validate Kubernetes input was added
				// But we can't inspect the builder directly
			},
		},
		{
			checkID: "sshd-service-enabled",
			validateFunc: func(t *testing.T, builder *celscanner.RuleBuilder) {
				// Would validate system input with is-enabled was added
			},
		},
		{
			checkID: "unknown-check",
			validateFunc: func(t *testing.T, builder *celscanner.RuleBuilder) {
				// Would validate file input was added as default
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.checkID, func(t *testing.T) {
			builder := celscanner.NewRuleBuilder(tt.checkID).
				SetExpression("true")

			err := s.addDefaultInputs(builder, tt.checkID)
			assert.NoError(t, err)

			// Build the rule to ensure it's valid
			rule, err := builder.Build()
			assert.NoError(t, err)
			assert.NotNil(t, rule)
			assert.Len(t, rule.Inputs(), 1, "Should have exactly one input")
		})
	}
}
