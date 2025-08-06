# CELScanner Plugin Mapping System

## Overview

The CELScanner Plugin uses a flexible mapping system to convert OSCAL RuleSets and Checks into CEL (Common Expression Language) rules. This system supports both stored rules (from the YAML rule store) and inline rule definitions.

## Key Concepts

### RuleSet to CEL Rules Mapping

- **One-to-Many**: A single OSCAL RuleSet can map to multiple CEL rules
- **Flexible Mapping**: Map by RuleSet.Rule.ID or individual Check.ID
- **Multiple Sources**: Use stored rules from the rule store or define rules inline

### Mapping Types

1. **Stored Rules**: Reference CEL rules stored in the YAML rule store
2. **Inline Rules**: Define CEL rules directly in the mapping configuration

## Mapping Configuration Format

```yaml
version: "1.0"

mappings:
  # Example: Map RuleSet ID to multiple stored rules
  sshd-service:
    type: stored_rules
    rule_ids:
      - sshd-service-enabled
      - sshd-service-running
    description: "SSH daemon service compliance checks"

  # Example: Map Check ID to inline rules
  pod-security:
    type: inline
    rules:
      - id: pod-security-context
        expression: "has(resource.spec.securityContext)"
        inputs:
          - name: resource
            type: kubernetes
            resource: pods
      - id: pod-non-root
        expression: "resource.spec.securityContext.runAsNonRoot == true"
        inputs:
          - name: resource
            type: kubernetes
            resource: pods
    description: "Pod security compliance checks"
```

## Mapping Resolution Process

1. **Load Mapping Config**: Load the YAML mapping configuration file
2. **Check RuleSet ID**: First, check if the RuleSet.Rule.ID has a mapping
3. **Check Individual Checks**: If no RuleSet mapping, check each Check.ID
4. **Fall Back to Built-in**: If no mappings found, use built-in mappings
5. **Generate CEL Rules**: Create CEL rules based on the mapping type

## Example Workflow

### 1. OSCAL Input
```go
RuleSet {
    Rule: {
        ID: "firewall-service",
        Description: "Ensure firewall is properly configured"
    },
    Checks: [
        {ID: "firewalld-enabled", Description: "Firewall enabled"},
        {ID: "firewalld-running", Description: "Firewall running"}
    ]
}
```

### 2. Mapping Configuration
```yaml
mappings:
  firewall-service:
    type: stored_rules
    rule_ids:
      - firewalld-enabled
      - firewalld-running
```

### 3. Generated CEL Rules
The plugin will:
1. Find the mapping for "firewall-service"
2. Load the stored rules "firewalld-enabled" and "firewalld-running"
3. Add RuleSet metadata to each CEL rule
4. Return both CEL rules for scanning

## Stored Rules Integration

When using `type: stored_rules`, the plugin:
1. Loads rules from the configured rule store directory
2. Converts StoredRule to CEL rule format
3. Preserves all rule metadata and configurations
4. Adds RuleSet context as extensions

## Inline Rules Features

When using `type: inline`, you can:
1. Define CEL expressions directly in the mapping
2. Specify inputs for each rule
3. Use parameter substitution (e.g., `${namespace}`)
4. Create rules without storing them separately

## Built-in Mappings

If no mapping file is configured or no mapping is found, the plugin uses built-in mappings:

```go
// System service checks
"sshd-service-enabled": `service.success && contains(service.output, "enabled")`
"firewalld-running": `service.success && contains(service.output, "active")`

// Kubernetes checks
"pod-security-context": "has(resource.spec.securityContext)"
"resource-limits": "resource.spec.containers.all(c, has(c.resources.limits))"
```

## Advanced Features

### Parameter Substitution
```yaml
parameters:
  namespace:
    default: "default"
    description: "Target namespace"

mappings:
  namespace-check:
    type: inline
    rules:
      - id: check-namespace
        expression: "resource.metadata.namespace == '${namespace}'"
```

### Templates
```yaml
templates:
  service-check:
    enabled:
      expression: 'service.success && contains(service.output, "enabled")'
    running:
      expression: 'service.success && contains(service.output, "active")'
```

### Severity Mappings
```yaml
severity_mappings:
  security: HIGH
  compliance: CRITICAL
  performance: MEDIUM
```

## Best Practices

1. **Use Stored Rules**: For reusable rules, store them in the rule store
2. **Group Related Checks**: Map RuleSets to logically related CEL rules
3. **Document Mappings**: Include descriptions for each mapping
4. **Version Control**: Keep mapping files in version control
5. **Test Mappings**: Validate that mappings produce expected CEL rules

## Troubleshooting

### No Rules Generated
- Check if mapping file exists and is valid YAML
- Verify RuleSet/Check IDs match mapping keys
- Check rule store initialization for stored rules
- Review logs for mapping errors

### Invalid CEL Rules
- Validate CEL expressions syntax
- Ensure all referenced inputs are defined
- Check for parameter substitution errors
- Verify input types match usage

### Performance Issues
- Use stored rules for better caching
- Limit inline rule complexity
- Consider rule grouping strategies
- Monitor rule store size

## Migration Guide

### From Simple Mappings
Old format:
```json
{
  "check-id": "expression"
}
```

New format:
```yaml
mappings:
  check-id:
    type: inline
    rules:
      - id: check-id
        expression: "expression"
        inputs: [...]
```

### From Multiple JSON Files
1. Combine mappings into single YAML file
2. Convert expressions to inline rules
3. Extract common rules to rule store
4. Update configuration to use new mapping file