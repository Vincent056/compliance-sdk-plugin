# CEL Go Scanner

A powerful, flexible compliance scanning library for Kubernetes and system resources using Google's Common Expression Language (CEL).

## Features

- **CEL-based Rules**: Write compliance rules using Google's CEL for powerful, expressive evaluations
- **Multi-Input Support**: Fetch data from Kubernetes clusters, filesystems, system commands, and HTTP APIs
- **Flexible Architecture**: Modular fetcher system supporting custom data sources
- **Live Cluster Integration**: Real-time scanning of live Kubernetes clusters
- **System Monitoring**: Monitor system health, services, and security configurations
- **Security-First**: Built-in security controls for safe system command execution
- **Rich Metadata**: Extensible metadata system for compliance frameworks (CIS, STIG, etc.)

## Quick Start

### Using Make Targets (Recommended)

Run examples easily with the provided Makefile targets:

```bash
# Run all examples
make examples

# Run specific examples
make example-basic             # Basic usage patterns
make example-complex           # Advanced CEL expressions  
make example-kubernetes        # Kubernetes resource scanning
make example-filesystem        # File and directory scanning
make example-system-monitoring # System health monitoring
make example-system-security   # Security compliance checks
make example-live-kubernetes   # Live cluster scanning (requires cluster)

# Build and manage examples
make build-examples            # Build all example binaries
make clean-examples            # Clean up example binaries
make help                      # Show all available targets
```

### Manual Usage

```bash
# Install dependencies
go mod tidy

# Run a specific example
cd examples/basic
go run main.go

# Run tests
go test ./...
```

## Examples

### 🔧 Basic Usage
```go
// Create a simple compliance rule
rule := celscanner.NewRuleBuilder("pod-security").
    WithKubernetesInput("pods", "", "v1", "pods", "default", "").
    SetExpression(`size(pods.items) > 0`).
    WithName("Pod Count Check").
    Build()

// Create scanner and run
scanner := celscanner.NewScanner(fetcher, logger)
results, err := scanner.Scan(ctx, celscanner.ScanConfig{Rules: []celscanner.CelRule{rule}})
```

### 🔒 System Security Monitoring
```go
// Monitor system security compliance
rule := celscanner.NewRuleBuilder("selinux-check").
    WithSystemInput("selinux", "", "getenforce", []string{}).
    SetExpression(`selinux.success && contains(selinux.output, "Enforcing")`).
    WithName("SELinux Enforcement").
    WithExtension("severity", "HIGH").
    Build()
```

### 🌐 Live Kubernetes Scanning
```go
// Scan live Kubernetes cluster
rule := celscanner.NewRuleBuilder("pod-security").
    WithKubernetesInput("pods", "", "v1", "pods", "", "").
    SetExpression(`pods.items.all(pod, has(pod.spec.securityContext))`).
    WithName("Pod Security Context").
    Build()
```

## Available Examples

| Example | Description | Make Target |
|---------|-------------|-------------|
| **Basic** | Fundamental usage patterns and API introduction | `make example-basic` |
| **Complex** | Advanced CEL expressions and rule composition | `make example-complex` |
| **Kubernetes** | Kubernetes resource scanning with mock data | `make example-kubernetes` |
| **Filesystem** | File and directory scanning patterns | `make example-filesystem` |
| **Live Kubernetes** | Real cluster scanning (requires kubeconfig) | `make example-live-kubernetes` |
| **System Monitoring** | System health and service monitoring | `make example-system-monitoring` |
| **System Security** | Security compliance and hardening checks | `make example-system-security` |

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   CEL Rules     │───▶│  Scanner Engine  │───▶│ Compliance      │
│                 │    │                  │    │ Results         │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                               │
                               ▼
                    ┌──────────────────┐
                    │ Composite Fetcher│
                    └──────────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
    ┌─────────────────┐ ┌─────────────┐ ┌─────────────────┐
    │ Kubernetes      │ │ System      │ │ Filesystem      │
    │ Fetcher         │ │ Fetcher     │ │ Fetcher         │
    └─────────────────┘ └─────────────┘ └─────────────────┘
```

## Fetchers

Fetchers are the core components that retrieve data from various sources for CEL rule evaluation. The library provides a flexible, extensible fetcher system that supports multiple input types and can be easily customized.

### 🔧 Quick Start with Fetchers

```go
// Create a composite fetcher with multiple capabilities
fetcher := fetchers.NewCompositeFetcherBuilder().
    WithKubernetes(client, clientset).           // Live Kubernetes API
    WithFilesystem("/etc").                      // Filesystem access
    WithSystem(false).                           // Safe system commands
    WithHTTP(30*time.Second, true, 3).          // HTTP APIs
    Build()

// Create scanner with fetcher
scanner := celscanner.NewScanner(fetcher, logger)
```

### 📋 Supported Input Types

| Input Type | Description | Use Cases |
|------------|-------------|-----------|
| **Kubernetes** | Fetch Kubernetes resources via API or files | Pod security, RBAC validation, resource compliance |
| **Filesystem** | Read files and directories with parsing | Configuration validation, secret scanning, policy checks |
| **System** | Execute system commands and check services | Service monitoring, security baselines, system health |
| **HTTP** | Make HTTP requests to APIs and services | API security, health checks, external validation |

### 🏗️ Composite Fetcher

The `CompositeFetcher` combines multiple specialized fetchers and automatically routes requests to the appropriate fetcher based on input type.

#### Creating a Composite Fetcher

```go
// Method 1: Using Builder Pattern (Recommended)
fetcher := fetchers.NewCompositeFetcherBuilder().
    WithKubernetes(client, clientset).
    WithFilesystem("").
    WithSystem(false).
    WithHTTP(30*time.Second, true, 3).
    Build()

// Method 2: Using Defaults
fetcher := fetchers.NewCompositeFetcherWithDefaults(
    client,                // Kubernetes client
    clientset,            // Kubernetes clientset
    "/path/to/api/files", // API resource path (for file-based)
    "/etc",               // Filesystem base path
    false,                // Allow arbitrary commands
)

// Method 3: Manual Configuration
fetcher := fetchers.NewCompositeFetcher()
fetcher.SetKubernetesFetcher(kubeFetcher)
fetcher.SetFilesystemFetcher(fileFetcher)
fetcher.SetSystemFetcher(systemFetcher)
fetcher.SetHTTPFetcher(httpFetcher)
```

#### Fetcher Capabilities

```go
// Check supported input types
supportedTypes := fetcher.GetSupportedInputTypes()
fmt.Printf("Supported: %v\n", supportedTypes)

// Validate inputs before scanning
inputs := []celscanner.Input{
    celscanner.NewKubernetesInput("pods", "", "v1", "pods", "", ""),
    celscanner.NewFileInput("config", "/etc/app.yaml", "yaml", false, false),
}

if err := fetcher.ValidateInputs(inputs); err != nil {
    log.Fatal("Invalid inputs:", err)
}
```

### 🎯 Kubernetes Fetcher

Retrieves Kubernetes resources from live clusters or pre-fetched files.

#### Live Cluster Access

```go
// Create clients
restConfig, _ := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
clientset, _ := kubernetes.NewForConfig(restConfig)
runtimeClient, _ := runtimeclient.New(restConfig, runtimeclient.Options{})

// Create fetcher
kubeFetcher := fetchers.NewKubernetesFetcher(runtimeClient, clientset)

// Use in rules
rule := celscanner.NewRuleBuilder("pod-security").
    WithKubernetesInput("pods", "", "v1", "pods", "default", "").
    SetExpression(`pods.items.all(pod, has(pod.spec.securityContext))`).
    Build()
```

#### File-Based Resources

```go
// Create file-based fetcher
kubeFetcher := fetchers.NewKubernetesFileFetcher("/path/to/api/resources")

// Fetcher reads from files like:
// /path/to/api/resources/pods.json
// /path/to/api/resources/configmaps.yaml
```

#### Configuration Options

```go
// Custom resource mappings
config := &fetchers.ResourceMappingConfig{
    CustomKindMappings: map[string]string{
        "customresource": "CustomResource",
    },
    CustomScopeMappings: map[schema.GroupVersionKind]bool{
        {Group: "custom.io", Version: "v1", Kind: "CustomResource"}: true,
    },
}

kubeFetcher := fetchers.NewKubernetesFetcher(client, clientset).
    WithConfig(config)
```

### 📁 Filesystem Fetcher

Reads and parses files and directories with support for various formats.

#### Basic File Reading

```go
// Create filesystem fetcher
fileFetcher := fetchers.NewFilesystemFetcher("/etc")

// Read YAML configuration
rule := celscanner.NewRuleBuilder("config-check").
    WithFileInput("config", "/etc/app/config.yaml", "yaml", false, false).
    SetExpression(`config.database.port == 5432`).
    Build()

// Read with permissions
rule := celscanner.NewRuleBuilder("secret-check").
    WithFileInput("secret", "/etc/app/secret.txt", "text", false, true).
    SetExpression(`secret.perm == "0600"`).
    Build()
```

#### Directory Scanning

```go
// Scan directory (non-recursive)
rule := celscanner.NewRuleBuilder("config-dir").
    WithFileInput("configs", "/etc/app/", "yaml", false, false).
    SetExpression(`size(configs) > 0`).
    Build()

// Recursive directory scan
rule := celscanner.NewRuleBuilder("all-configs").
    WithFileInput("all", "/etc/app/", "yaml", true, false).
    SetExpression(`size(all) > 5`).
    Build()
```

#### Supported Formats

| Format | Description | Auto-Detection |
|--------|-------------|----------------|
| `yaml` | YAML files | `.yaml`, `.yml` |
| `json` | JSON files | `.json` |
| `text` | Plain text | Default |
| `auto` | Auto-detect | Based on extension |

#### File Metadata

When `checkPermissions` is enabled, files include metadata:

```go
// Access file metadata in CEL
rule := celscanner.NewRuleBuilder("file-security").
    WithFileInput("secret", "/etc/secret", "text", false, true).
    SetExpression(`
        secret.content != "" && 
        secret.perm == "0600" && 
        secret.owner == "root"
    `).
    Build()
```

### 🖥️ System Fetcher

Executes system commands and checks service status with security controls.

#### Service Status Checking

```go
// Check systemd service
rule := celscanner.NewRuleBuilder("nginx-status").
    WithSystemInput("nginx", "nginx", "", []string{}).
    SetExpression(`nginx.success && nginx.status == "active"`).
    Build()

// Multiple services
rule := celscanner.NewRuleBuilder("services").
    WithSystemInput("ssh", "sshd", "", []string{}).
    WithSystemInput("firewall", "firewalld", "", []string{}).
    SetExpression(`ssh.success && firewall.success`).
    Build()
```

#### Command Execution

```go
// Safe commands (allowlisted)
rule := celscanner.NewRuleBuilder("selinux-check").
    WithSystemInput("selinux", "", "getenforce", []string{}).
    SetExpression(`selinux.success && selinux.output == "Enforcing"`).
    Build()

// Custom commands (requires allowArbitraryCommands: true)
rule := celscanner.NewRuleBuilder("custom-check").
    WithSystemInput("uptime", "", "uptime", []string{}).
    SetExpression(`uptime.success && uptime.exitCode == 0`).
    Build()
```

#### Security Configuration

```go
// Safe mode (default) - only allowlisted commands
systemFetcher := fetchers.NewSystemFetcher(30*time.Second, false)

// Unsafe mode - allows arbitrary commands (use with caution)
systemFetcher := fetchers.NewSystemFetcher(30*time.Second, true)

// Use in composite fetcher
fetcher := fetchers.NewCompositeFetcherBuilder().
    WithSystem(false). // Safe mode
    Build()
```

#### Helper Functions

```go
// Direct service checks
active := fetchers.IsServiceActive("nginx")
enabled := fetchers.IsServiceEnabled("nginx")

// Direct command execution
result, err := fetchers.ExecuteCommand("hostname", []string{})
if err == nil && result.Success {
    fmt.Println("Hostname:", result.Output)
}

// System information
info, err := fetchers.GetSystemInfo()
```

### 🌐 HTTP Fetcher

Performs HTTP requests for API security scanning and health checks.

#### Basic HTTP Requests

```go
// GET request
rule := celscanner.NewRuleBuilder("api-health").
    WithHTTPInput("health", "https://api.example.com/health", "GET", nil, nil).
    SetExpression(`health.success && health.statusCode == 200`).
    Build()

// POST request with JSON
payload := []byte(`{"query": "security scan"}`)
headers := map[string]string{
    "Content-Type": "application/json",
    "Authorization": "Bearer " + token,
}

rule := celscanner.NewRuleBuilder("api-search").
    WithHTTPInput("search", "https://api.example.com/search", "POST", headers, payload).
    SetExpression(`search.success && size(search.body.results) > 0`).
    Build()
```

#### Security Headers Validation

```go
rule := celscanner.NewRuleBuilder("security-headers").
    WithHTTPInput("headers", "https://app.example.com", "GET", nil, nil).
    SetExpression(`
        headers.success && 
        has(headers.headers["X-Frame-Options"]) && 
        has(headers.headers["X-Content-Type-Options"])
    `).
    Build()
```

#### Authentication Testing

```go
// Test protected endpoint
rule := celscanner.NewRuleBuilder("auth-required").
    WithHTTPInput("protected", "https://api.example.com/admin", "GET", nil, nil).
    SetExpression(`!protected.success && protected.statusCode == 401`).
    Build()

// Test with authentication
headers := map[string]string{"Authorization": "Bearer " + token}
rule := celscanner.NewRuleBuilder("auth-success").
    WithHTTPInput("authed", "https://api.example.com/admin", "GET", headers, nil).
    SetExpression(`authed.success && authed.statusCode == 200`).
    Build()
```

#### Performance Monitoring

```go
rule := celscanner.NewRuleBuilder("performance").
    WithHTTPInput("api", "https://api.example.com/fast", "GET", nil, nil).
    SetExpression(`api.success && api.responseTime < 1000`). // < 1 second
    Build()
```

#### Configuration Options

```go
// Custom HTTP fetcher
httpFetcher := fetchers.NewHTTPFetcher(
    10*time.Second, // timeout
    false,          // don't follow redirects
    5,              // max retries
)

// Use in composite fetcher
fetcher := fetchers.NewCompositeFetcherBuilder().
    WithHTTP(10*time.Second, false, 5).
    Build()
```

### 🔧 Custom Fetchers

Extend the system with custom input fetchers for specialized data sources.

#### Creating Custom Fetchers

```go
// Define custom input type
const InputTypeDatabase celscanner.InputType = "database"

// Implement custom fetcher
type DatabaseFetcher struct {
    connectionString string
}

func (d *DatabaseFetcher) FetchInputs(inputs []celscanner.Input, variables []celscanner.CelVariable) (map[string]interface{}, error) {
    // Custom implementation
    return map[string]interface{}{
        "users": []map[string]interface{}{
            {"id": 1, "name": "admin", "active": true},
        },
    }, nil
}

func (d *DatabaseFetcher) SupportsInputType(inputType celscanner.InputType) bool {
    return inputType == InputTypeDatabase
}
```

#### Registering Custom Fetchers

```go
// Register with composite fetcher
customFetcher := &DatabaseFetcher{connectionString: "..."}
fetcher := fetchers.NewCompositeFetcherBuilder().
    WithCustomFetcher(InputTypeDatabase, customFetcher).
    Build()

// Use in rules
rule := celscanner.NewRuleBuilder("db-check").
    WithCustomInput("users", InputTypeDatabase, customSpec).
    SetExpression(`size(users) > 0`).
    Build()
```

### 📊 Response Structures

Each fetcher returns structured data that can be used in CEL expressions:

#### Kubernetes Response
```json
{
  "apiVersion": "v1",
  "kind": "PodList",
  "items": [
    {
      "metadata": {"name": "pod1", "namespace": "default"},
      "spec": {"containers": [...]}
    }
  ]
}
```

#### File Response
```json
{
  "content": {...},     // Parsed content
  "mode": "0644",       // File mode
  "perm": "0644",       // Permissions
  "owner": "root",      // Owner
  "group": "root",      // Group
  "size": 1024          // Size in bytes
}
```

#### System Response
```json
{
  "status": "active",
  "output": "nginx is running",
  "error": "",
  "exitCode": 0,
  "success": true,
  "metadata": {
    "command": "systemctl",
    "timestamp": 1640995200
  }
}
```

#### HTTP Response
```json
{
  "statusCode": 200,
  "success": true,
  "headers": {
    "Content-Type": ["application/json"],
    "X-Frame-Options": ["DENY"]
  },
  "body": {...},        // Parsed JSON or raw text
  "rawBody": "...",     // Raw response body
  "responseTime": 150,  // Response time in milliseconds
  "metadata": {
    "url": "https://api.example.com",
    "method": "GET"
  }
}
```

### 🛠️ Advanced Usage

#### Mixed Input Types

```go
// Comprehensive system check
rule := celscanner.NewRuleBuilder("system-compliance").
    WithKubernetesInput("pods", "", "v1", "pods", "", "").
    WithFileInput("config", "/etc/app/config.yaml", "yaml", false, false).
    WithSystemInput("nginx", "nginx", "", []string{}).
    WithHTTPInput("health", "https://api.example.com/health", "GET", nil, nil).
    SetExpression(`
        size(pods.items) > 0 && 
        config.monitoring.enabled == true && 
        nginx.success && 
        health.statusCode == 200
    `).
    Build()
```

#### Error Handling

```go
// Graceful error handling in CEL
rule := celscanner.NewRuleBuilder("robust-check").
    WithHTTPInput("api", "https://api.example.com/health", "GET", nil, nil).
    SetExpression(`
        // Check if request succeeded
        api.success ? 
            (api.statusCode == 200 && has(api.body.status)) : 
            false  // Fail if request failed
    `).
    Build()
```

#### Conditional Fetching

```go
// Use variables to control fetching
variables := []celscanner.CelVariable{
    fetchers.NewCelVariable("environment", "", "production", schema.GroupVersionKind{}),
}

rule := celscanner.NewRuleBuilder("env-specific").
    WithFileInput("config", "/etc/app/config.yaml", "yaml", false, false).
    SetExpression(`
        environment == "production" ? 
            (config.database.ssl == true) : 
            true  // Skip SSL check in non-production
    `).
    Build()
```

### 📚 Best Practices

1. **Security First**: Use safe mode for system commands in production
2. **Error Handling**: Always check success flags in CEL expressions
3. **Performance**: Use appropriate timeouts for HTTP requests
4. **Validation**: Validate inputs before scanning
5. **Logging**: Enable debug logging for troubleshooting
6. **Caching**: Consider caching for expensive operations
7. **Permissions**: Use minimal file permissions checking when possible

### 🔍 Troubleshooting

#### Common Issues

```bash
# Check fetcher capabilities
supportedTypes := fetcher.GetSupportedInputTypes()

# Validate inputs
err := fetcher.ValidateInputs(inputs)

# Enable debug logging
config := celscanner.ScanConfig{
    EnableDebugLogging: true,
    // ... other config
}
```

#### Debug Mode

```go
// Enable detailed logging
scanner := celscanner.NewScanner(fetcher, &celscanner.DebugLogger{})

// Check individual fetcher status
fmt.Printf("Kubernetes: %v\n", fetcher.SupportsInputType(celscanner.InputTypeKubernetes))
fmt.Printf("Filesystem: %v\n", fetcher.SupportsInputType(celscanner.InputTypeFile))
```

## Development

```bash
# Run tests with coverage
make test-coverage

# Format and lint code
make quality

# Build project
make build

# See all available targets
make help
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details. 