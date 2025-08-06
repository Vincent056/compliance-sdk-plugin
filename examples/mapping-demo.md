# Mapping System Demo

This example demonstrates how the CELScanner Plugin mapping system works with OSCAL RuleSets.

## Scenario

You have an OSCAL policy with a RuleSet for SSH compliance that needs to check:
1. SSH service is enabled
2. SSH service is running
3. SSH configuration is secure

## OSCAL Input (from complyctl)

```go
RuleSet {
    Rule: {
        ID: "ssh-compliance",
        Description: "Ensure SSH is properly configured and running",
        Parameters: [
            {ID: "port", Value: "22"},
        ],
    },
    Checks: [
        {ID: "sshd-enabled", Description: "SSH daemon enabled"},
        {ID: "sshd-running", Description: "SSH daemon running"},
        {ID: "ssh-config-secure", Description: "SSH config is secure"},
    ],
}
```

## Mapping Configuration

```yaml
# mappings.yaml
version: "1.0"

mappings:
  # Map the entire RuleSet to multiple CEL rules
  ssh-compliance:
    type: stored_rules
    rule_ids:
      - sshd-service-enabled
      - sshd-service-running
      - ssh-root-login-disabled
      - ssh-password-auth-disabled
    description: "Complete SSH compliance check suite"

  # Alternative: Map individual checks
  ssh-config-secure:
    type: inline
    rules:
      - id: ssh-root-login
        expression: 'config.content.contains("PermitRootLogin no")'
        inputs:
          - name: config
            type: file
            path: /etc/ssh/sshd_config
      - id: ssh-password-auth
        expression: 'config.content.contains("PasswordAuthentication no")'
        inputs:
          - name: config
            type: file
            path: /etc/ssh/sshd_config
```

## Generated CEL Rules

The plugin will generate these CEL rules:

### From stored_rules mapping:
```yaml
- id: sshd-service-enabled
  expression: 'service.success && contains(service.output, "enabled")'
  metadata:
    oscal_rule_id: ssh-compliance
    ruleset_description: "Ensure SSH is properly configured and running"

- id: sshd-service-running
  expression: 'service.success && contains(service.output, "active")'
  metadata:
    oscal_rule_id: ssh-compliance
    ruleset_description: "Ensure SSH is properly configured and running"

- id: ssh-root-login-disabled
  expression: '!config.content.contains("PermitRootLogin yes")'
  metadata:
    oscal_rule_id: ssh-compliance
    ruleset_description: "Ensure SSH is properly configured and running"

- id: ssh-password-auth-disabled
  expression: 'config.content.contains("PasswordAuthentication no")'
  metadata:
    oscal_rule_id: ssh-compliance
    ruleset_description: "Ensure SSH is properly configured and running"
```

## Processing Flow

1. **Receive RuleSet**: Plugin receives the OSCAL RuleSet from complyctl
2. **Check Mapping**: Looks for "ssh-compliance" in mappings
3. **Find Mapping**: Found `type: stored_rules` with 4 rule IDs
4. **Load Rules**: Loads each rule from the rule store
5. **Add Metadata**: Adds RuleSet metadata to each CEL rule
6. **Return Rules**: Returns all 4 CEL rules for scanning

## Fallback Behavior

If no mapping was found for "ssh-compliance":
1. Check each Check ID ("sshd-enabled", "sshd-running", "ssh-config-secure")
2. If still no mapping, use built-in mappings
3. If no built-in mapping, skip the check with a warning

## Benefits

1. **Flexibility**: Map one RuleSet to many CEL rules
2. **Reusability**: Store common rules and reference them
3. **Maintainability**: Update mappings without changing code
4. **Extensibility**: Add new mappings without plugin updates