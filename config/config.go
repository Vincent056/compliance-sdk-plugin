// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/hashicorp/go-hclog"
)

const (
	PluginDir   string = "celscanner"
	PolicyDir   string = "policy"
	ResultsDir  string = "results"
	MappingsDir string = "mappings"
)

type Config struct {
	// Files configuration
	Files struct {
		Workspace   string `config:"workspace"`
		MappingFile string `config:"mapping_file"`
		RulesFile   string `config:"rules_file"`
		ResultsFile string `config:"results_file"`
	}

	// Parameters configuration
	Parameters struct {
		Profile    string `config:"profile"`
		TargetName string `config:"target_name"`
		TargetType string `config:"target_type"`
		TargetID   string `config:"target_id"`
		Namespace  string `config:"namespace"`
	}

	// CEL RPC Server configuration
	CELServer struct {
		Address  string `config:"cel_server_address"`
		Timeout  int    `config:"cel_server_timeout"`
		UseTLS   bool   `config:"cel_server_use_tls"`
		CertFile string `config:"cel_server_cert_file"`
		KeyFile  string `config:"cel_server_key_file"`
	}

	// Feature flags
	Features struct {
		KubernetesEnabled bool `config:"enable_kubernetes"`
		FilesystemEnabled bool `config:"enable_filesystem"`
		HTTPEnabled       bool `config:"enable_http"`
		SystemEnabled     bool `config:"enable_system"`
		UseRPCServer      bool `config:"use_rpc_server"`
	}

	// Scanner configuration
	Scanner struct {
		EnableDebugLogging bool     `config:"enable_debug_logging"`
		IncludeNamespaces  []string `config:"include_namespaces"`
		ExcludeNamespaces  []string `config:"exclude_namespaces"`
		ResourceTypes      []string `config:"resource_types"`
	}
}

// NewConfig creates a new, empty Config.
func NewConfig() *Config {
	cfg := &Config{}
	// Set defaults
	cfg.Features.FilesystemEnabled = true
	cfg.Parameters.TargetType = "system"
	cfg.CELServer.Timeout = 30
	return cfg
}

// LoadSettings sets the values in the Config from a given config map and
// performs validation.
func (c *Config) LoadSettings(config map[string]string) error {
	// Load Files configuration
	filesVal := reflect.ValueOf(&c.Files).Elem()
	if err := setConfigStruct(filesVal, config); err != nil {
		return fmt.Errorf("failed to set files config: %w", err)
	}

	// Load Parameters configuration
	paramVal := reflect.ValueOf(&c.Parameters).Elem()
	if err := setConfigStruct(paramVal, config); err != nil {
		return fmt.Errorf("failed to set parameters config: %w", err)
	}

	// Load CEL Server configuration
	celServerVal := reflect.ValueOf(&c.CELServer).Elem()
	if err := setConfigStruct(celServerVal, config); err != nil {
		return fmt.Errorf("failed to set CEL server config: %w", err)
	}

	// Load Features configuration
	featuresVal := reflect.ValueOf(&c.Features).Elem()
	if err := setConfigStruct(featuresVal, config); err != nil {
		return fmt.Errorf("failed to set features config: %w", err)
	}

	// Load Scanner configuration
	scannerVal := reflect.ValueOf(&c.Scanner).Elem()
	if err := setConfigStruct(scannerVal, config); err != nil {
		return fmt.Errorf("failed to set scanner config: %w", err)
	}

	// Handle array fields separately
	if namespaces, ok := config["include_namespaces"]; ok {
		c.Scanner.IncludeNamespaces = strings.Split(namespaces, ",")
	}
	if namespaces, ok := config["exclude_namespaces"]; ok {
		c.Scanner.ExcludeNamespaces = strings.Split(namespaces, ",")
	}
	if resources, ok := config["resource_types"]; ok {
		c.Scanner.ResourceTypes = strings.Split(resources, ",")
	}

	return c.validate()
}

// validate checks that the configuration is valid
func (c *Config) validate() error {
	// Validate workspace
	if c.Files.Workspace == "" {
		return fmt.Errorf("workspace is required")
	}

	// Create workspace directory if it doesn't exist
	if err := os.MkdirAll(c.Files.Workspace, 0750); err != nil {
		return fmt.Errorf("failed to create workspace directory: %w", err)
	}

	// Create subdirectories
	dirs := []string{
		filepath.Join(c.Files.Workspace, PluginDir),
		filepath.Join(c.Files.Workspace, PluginDir, PolicyDir),
		filepath.Join(c.Files.Workspace, PluginDir, ResultsDir),
		filepath.Join(c.Files.Workspace, PluginDir, MappingsDir),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Set default file paths if not specified
	if c.Files.RulesFile == "" {
		c.Files.RulesFile = filepath.Join(c.Files.Workspace, PluginDir, PolicyDir, "cel-rules.yaml")
	}

	if c.Files.ResultsFile == "" {
		c.Files.ResultsFile = filepath.Join(c.Files.Workspace, PluginDir, ResultsDir, "cel-results.yaml")
	}

	// Validate CEL server configuration if RPC is enabled
	if c.Features.UseRPCServer && c.CELServer.Address == "" {
		return fmt.Errorf("CEL server address is required when RPC is enabled")
	}

	// Validate TLS configuration
	if c.CELServer.UseTLS {
		if c.CELServer.CertFile == "" || c.CELServer.KeyFile == "" {
			return fmt.Errorf("certificate and key files are required when TLS is enabled")
		}

		// Check if cert files exist
		if _, err := os.Stat(c.CELServer.CertFile); err != nil {
			return fmt.Errorf("certificate file not found: %w", err)
		}
		if _, err := os.Stat(c.CELServer.KeyFile); err != nil {
			return fmt.Errorf("key file not found: %w", err)
		}
	}

	// Validate target configuration
	if c.Parameters.TargetName == "" {
		// Set default target name
		hostname, err := os.Hostname()
		if err != nil {
			c.Parameters.TargetName = "unknown"
		} else {
			c.Parameters.TargetName = hostname
		}
	}

	if c.Parameters.TargetID == "" {
		c.Parameters.TargetID = c.Parameters.TargetName
	}

	hclog.Default().Debug("Configuration validated successfully")
	return nil
}

// setConfigStruct uses reflection to set struct fields from a config map
func setConfigStruct(structVal reflect.Value, config map[string]string) error {
	structType := structVal.Type()

	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i)
		fieldVal := structVal.Field(i)

		// Get the config tag
		configTag := field.Tag.Get("config")
		if configTag == "" {
			continue
		}

		// Get the value from config map
		value, ok := config[configTag]
		if !ok {
			continue
		}

		// Set the field value based on its type
		switch fieldVal.Kind() {
		case reflect.String:
			fieldVal.SetString(value)
		case reflect.Bool:
			fieldVal.SetBool(strings.ToLower(value) == "true")
		case reflect.Int:
			var intVal int
			if _, err := fmt.Sscanf(value, "%d", &intVal); err != nil {
				return fmt.Errorf("invalid int value for %s: %s", configTag, value)
			}
			fieldVal.SetInt(int64(intVal))
		case reflect.Slice:
			// Skip slice fields - they are handled separately in LoadSettings
			continue
		default:
			return fmt.Errorf("unsupported field type for %s: %s", configTag, fieldVal.Kind())
		}
	}

	return nil
}
