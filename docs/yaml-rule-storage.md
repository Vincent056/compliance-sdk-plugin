# YAML Rule Storage Documentation

## Overview

The CELScanner Plugin includes a comprehensive YAML-based rule storage system that provides persistent storage, version control compatibility, and easy rule management.

## Features

### 1. Individual File Storage
Each rule is stored as a separate YAML file, enabling:
- Easy version control tracking
- Individual rule updates without affecting others
- Simple file-based backups
- Direct rule editing with text editors

### 2. Rule Structure

Rules are stored in the following YAML format:

```yaml
id: unique-rule-id
name: Human Readable Rule Name
description: Detailed description of what the rule checks
expression: 'CEL expression for validation'
inputs:
  - name: input_variable_name
    type: kubernetes|file|http|system
    # Type-specific fields...
tags:
  - security
  - compliance
category: rule-category
severity: CRITICAL|HIGH|MEDIUM|LOW
extensions:
  key: value
  # Additional metadata
created_at: 2024-01-01T00:00:00Z
updated_at: 2024-01-01T00:00:00Z
created_by: username
check_id: oscal-check-id
```

## Input Types

### Kubernetes Input
```yaml
inputs:
  - name: resource
    type: kubernetes
    resource: pods  # Resource type (pods, deployments, etc.)
```

### File Input
```yaml
inputs:
  - name: config
    type: file
    path: /etc/config.conf
```

### HTTP Input
```yaml
inputs:
  - name: api
    type: http
    url: https://api.example.com/health
```

### System Input (Limited to Service Status)
```yaml
inputs:
  - name: service
    type: system
    command: systemctl
    args: [is-active, sshd]
```

## API Usage

### Creating a Rule Store
```go
store, err := NewRuleStore("/path/to/rules/directory")
if err != nil {
    log.Fatal("Failed to create rule store:", err)
}
```

### Saving Rules
```go
rule := &StoredRule{
    ID:          "custom-security-check",
    Name:        "Custom Security Check",
    Description: "Validates security configuration",
    Expression:  "resource.secure == true",
    Inputs: []RuleInputConfig{
        {
            Name:     "resource",
            Type:     "kubernetes",
            Resource: "pods",
        },
    },
    Tags:     []string{"security", "custom"},
    Category: "security",
    Severity: "HIGH",
}

err := store.Save(rule)
```

### Retrieving Rules
```go
// Get a specific rule
rule, err := store.Get("custom-security-check")

// List all rules
allRules := store.List(nil)

// List filtered rules
securityRules := store.List(map[string]string{
    "category": "security",
    "severity": "HIGH",
})
```

### Converting to CEL Rules
```go
storedRule, _ := store.Get("rule-id")
celRule, err := store.ConvertToCelRule(storedRule)
if err != nil {
    log.Fatal("Conversion failed:", err)
}

// Use with scanner
scanner.Scan(context.Background(), celscanner.ScanConfig{
    Rules: []celscanner.CelRule{celRule},
})
```

### Import/Export

#### Export Rules
```go
// Export all rules
err := store.ExportRules(nil, "/path/to/export.yaml")

// Export specific rules
err := store.ExportRules([]string{"rule1", "rule2"}, "/path/to/export.yaml")
```

#### Import Rules
```go
// Import rules (skip existing)
err := store.ImportRules("/path/to/import.yaml", false)

// Import rules (overwrite existing)
err := store.ImportRules("/path/to/import.yaml", true)
```

## File Organization

```
rules/
├── kubernetes/
│   ├── pod-security-context.yaml
│   ├── container-limits.yaml
│   └── privileged-containers.yaml
├── system/
│   ├── sshd-service-enabled.yaml
│   ├── firewalld-running.yaml
│   └── selinux-enforcing.yaml
└── custom/
    └── organization-specific.yaml
```

## Best Practices

1. **Rule Naming**: Use descriptive IDs that indicate the check purpose
2. **Categories**: Use consistent category names for better organization
3. **Tags**: Apply relevant tags for easy filtering
4. **Documentation**: Include comprehensive descriptions
5. **Version Control**: Commit rule changes with meaningful messages
6. **Testing**: Include test cases in rule extensions when possible

## Integration with CELScanner Plugin

The rule store integrates seamlessly with the CELScanner plugin:

1. Rules are loaded from the configured directory
2. OSCAL checks are mapped to stored rules
3. Rules are converted to CEL format for execution
4. Results are mapped back to OSCAL format

## Security Considerations

### System Commands
- System inputs are restricted to service status checks only
- No arbitrary command execution is allowed
- Supported commands:
  - `systemctl is-active <service>`
  - `systemctl is-enabled <service>`
  - `getenforce` (for SELinux)

### File Permissions
- Rule files should be readable by the plugin process
- Write permissions needed only for rule management operations
- Consider using read-only mounts in production

## Migration from Other Formats

### From JSON
```go
// Example JSON to YAML migration
jsonData, _ := ioutil.ReadFile("rules.json")
var rules []StoredRule
json.Unmarshal(jsonData, &rules)

for _, rule := range rules {
    store.Save(&rule)
}
```

### From Inline Rules
```go
// Convert inline CEL rules to stored format
celRule := celscanner.NewRuleBuilder("example").
    WithName("Example Rule").
    SetExpression("resource.valid == true").
    Build()

storedRule := &StoredRule{
    ID:          celRule.Identifier(),
    Name:        celRule.Metadata().Name,
    Expression:  celRule.Expression(),
    // Map other fields...
}
store.Save(storedRule)
```

## Troubleshooting

### Common Issues

1. **Rule Not Loading**
   - Check YAML syntax
   - Verify file permissions
   - Check logs for parsing errors

2. **Expression Errors**
   - Validate CEL syntax
   - Ensure input names match expression variables
   - Check input type compatibility

3. **Performance**
   - Use filtering to limit rule sets
   - Consider rule caching for large deployments
   - Monitor file system performance

## Future Enhancements

1. **Rule Versioning**: Track rule history and changes
2. **Rule Templates**: Reusable rule patterns
3. **Rule Validation**: Pre-execution syntax checking
4. **Rule Dependencies**: Define rule execution order
5. **Rule Metrics**: Track rule performance and results