# Kubeconfig Handling in CELScanner Plugin

## Overview

The CELScanner Plugin uses a flexible approach for discovering and using kubeconfig files for Kubernetes authentication. This ensures the plugin works in various environments without hardcoding paths.

## Discovery Order

The plugin searches for kubeconfig in the following order:

1. **Environment Variable**: `KUBECONFIG`
2. **Default Location**: `~/.kube/config`
3. **In-Cluster**: When running inside a Kubernetes pod

## Implementation

### Server Code

The `getKubeconfigPath()` method in `server.go` handles the discovery:

```go
func (s *PluginServer) getKubeconfigPath() string {
    // 1. Check KUBECONFIG environment variable
    if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
        return kubeconfig
    }
    
    // 2. Check default location
    if home, err := os.UserHomeDir(); err == nil {
        kubeconfigPath := filepath.Join(home, ".kube", "config")
        if _, err := os.Stat(kubeconfigPath); err == nil {
            return kubeconfigPath
        }
    }
    
    // 3. Return empty (will try in-cluster config)
    return ""
}
```

### Test Code

Integration tests use the same approach via `getTestKubeconfig()`:

```go
func getTestKubeconfig(t *testing.T) string {
    // Same logic as server, but with test logging
}
```

## Usage Examples

### Default Configuration
```bash
# Uses ~/.kube/config
./celscanner-plugin
```

### Custom Kubeconfig
```bash
# Uses specified kubeconfig
KUBECONFIG=/path/to/custom/config ./celscanner-plugin
```

### Integration Tests
```bash
# Default location
go test -tags=integration ./server

# Custom location
KUBECONFIG=/custom/path go test -tags=integration ./server
```

## Benefits

1. **No Hardcoded Paths**: Works on any system without modification
2. **Environment Flexibility**: Easy to override for different environments
3. **Standard Kubernetes Behavior**: Follows the same pattern as kubectl
4. **Test Consistency**: Tests use the same discovery logic as production code

## Troubleshooting

### No Kubeconfig Found

If the plugin cannot find a kubeconfig:

1. Check if `KUBECONFIG` environment variable is set correctly
2. Verify `~/.kube/config` exists and is readable
3. For in-cluster operation, ensure proper RBAC permissions

### Debug Logging

Enable debug logging to see which kubeconfig is being used:

```yaml
scanner:
  enable_debug_logging: true
```

The log will show:
```
[DEBUG] Using kubeconfig: path=/home/user/.kube/config
```