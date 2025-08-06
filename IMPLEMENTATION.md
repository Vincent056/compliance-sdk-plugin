# CELScanner Plugin Implementation Summary

## Overview

This document summarizes the implementation of the CELScanner Plugin for complyctl, including key design decisions, security considerations, and technical details.

## Key Features Implemented

### 1. YAML-Based Configuration and Storage
- All rules and results are stored in YAML format for better readability
- Configuration uses YAML instead of JSON
- Rule storage system supports individual YAML files per rule

### 2. Advanced Mapping System
- **One-to-Many Mapping**: One OSCAL RuleSet can map to multiple CEL rules
- **Flexible Sources**: Support for both stored rules and inline definitions
- **Hierarchical Lookup**: Map by RuleSet.Rule.ID or individual Check.ID
- **Mapping Types**:
  - `stored_rules`: Reference rules from the YAML rule store
  - `inline`: Define CEL rules directly in the mapping configuration

### 3. System Security Restrictions
- System command execution is LIMITED to service status checks only
- Supported commands:
  - `systemctl is-active <service>`
  - `systemctl is-enabled <service>`
  - `getenforce` (SELinux status)
- No arbitrary command execution allowed

### 4. Kubernetes Integration
- Full support for scanning Kubernetes resources
- Automatic client configuration from kubeconfig
- Support for both in-cluster and out-of-cluster operation
- Integration tested with live clusters
- Kubeconfig discovery order:
  1. `KUBECONFIG` environment variable
  2. Default location: `~/.kube/config`
  3. In-cluster configuration (when running in a pod)

### 5. Rule Management
- YAML-based rule store with import/export capabilities
- Automatic conversion between stored rules and CEL scanner format
- Support for rule filtering by category, severity, and tags
- Version control friendly storage format

## Technical Implementation Details

### Mapping System Architecture
```go
// Mapping flow
RuleSet.Rule.ID → MappingConfig → MappingDefinition → CEL Rules[]
                ↓ (fallback)
        Check.ID → MappingDefinition → CEL Rules[]
                ↓ (fallback)
        Built-in mappings → Single CEL Rule
```

#### Key Methods:
- `getCELRulesForRuleSet()`: Main entry point for rule mapping
- `processMappingDefinition()`: Handles stored_rules vs inline types
- `createCELRuleFromInline()`: Creates CEL rules from inline definitions
- `createDefaultCELRule()`: Falls back to built-in mappings

### System Input Pattern
Following the cel-go-scanner pattern:
```go
// Service status check
WithSystemInput("service", "", "systemctl", []string{"is-active", "sshd"})

// SELinux check
WithSystemInput("selinux", "", "getenforce", []string{})
```

### Expression Validation
System expressions check both success and output:
```cel
service.success && contains(service.output, "active")
```

### Configuration Structure
```go
type Config struct {
    Files struct {
        Workspace   string
        MappingFile string
        RulesFile   string
        ResultsFile string
    }
    Features struct {
        KubernetesEnabled bool
        SystemEnabled     bool  // Limited to service status
        // ...
    }
}
```

## Security Considerations

1. **System Commands**: Strictly limited to service status queries
2. **File Access**: Controlled through configuration
3. **Network Access**: Limited to configured endpoints
4. **Kubernetes Access**: Uses standard RBAC permissions

## Testing

### Unit Tests
- Comprehensive unit tests for all major components
- Mock-based testing for external dependencies
- Test coverage for YAML serialization/deserialization

### Integration Tests
- Live Kubernetes cluster testing
- Service status check validation
- End-to-end workflow testing

### Test Commands
```bash
# Run all tests
make test

# Run integration tests with custom kubeconfig
KUBECONFIG=/home/vincent/.kube/config make test-k8s

# Run specific test
go test -v ./server -run TestSystemServiceChecks
```

## File Structure
```
celscanner-plugin/
├── main.go                 # Plugin entry point
├── server/
│   ├── server.go          # Policy provider implementation
│   ├── rulestore.go       # YAML rule storage
│   ├── server_test.go     # Unit tests
│   ├── system_test.go     # System service tests
│   └── server_integration_test.go  # Integration tests
├── config/
│   └── config.go          # Configuration structures
├── examples/
│   ├── manifest.yaml      # Complyctl manifest
│   ├── mappings.json      # CEL expression mappings
│   └── rules/            # Example YAML rules
├── docs/
│   └── yaml-rule-storage.md  # Rule storage documentation
├── README.md              # Main documentation
├── IMPLEMENTATION.md      # This file
└── Makefile              # Build and test automation
```

## Key Design Decisions

1. **YAML over JSON**: Better readability and consistency with Kubernetes ecosystem
2. **Limited System Access**: Security-first approach, only allowing specific service checks
3. **Plugin Architecture**: Clean separation between complyctl integration and CEL scanning
4. **Rule Storage**: Individual files for version control compatibility
5. **Kubernetes-Native**: First-class support for Kubernetes resources

## Future Enhancements

1. **Custom Service Fetcher**: Implement a dedicated service status fetcher with additional security controls
2. **Rule Versioning**: Track rule changes over time
3. **Performance Optimization**: Caching and parallel execution improvements
4. **Extended Compliance Frameworks**: Support for additional standards beyond OSCAL

## Troubleshooting

### Common Issues

1. **Configuration Loading Error**: Check YAML syntax and field types
2. **Kubernetes Connection**: Verify kubeconfig and cluster access
3. **System Checks Failing**: Ensure service names are correct and permissions are adequate
4. **Rule Conversion**: Validate CEL expressions and input configurations

### Debug Mode
Enable debug logging in configuration:
```yaml
scanner:
  enable_debug_logging: true
```

## References

- [CEL Go Scanner](https://github.com/Vincent056/cel-go-scanner)
- [Complyctl Documentation](https://github.com/complytime/complyctl)
- [OSCAL Documentation](https://pages.nist.gov/OSCAL/)
- [CEL Specification](https://github.com/google/cel-spec)