// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// ensureWorkspaceDirs creates necessary subdirectories in the workspace
func ensureWorkspaceDirs(workspace string) error {
	dirs := []string{
		filepath.Join(workspace, "celscanner", "policy"),
		filepath.Join(workspace, "celscanner", "results"),
		filepath.Join(workspace, "rules"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}
	return nil
}

// setupTestWorkspace creates a test workspace. If TEST_WORKSPACE env is set,
// it uses that directory. Otherwise, it creates a temp directory and copies
// the examples folder content to it.
func setupTestWorkspace(t *testing.T) string {
	// Check if workspace is provided via environment
	if workspace := os.Getenv("TEST_WORKSPACE"); workspace != "" {
		t.Logf("Using workspace from TEST_WORKSPACE env: %s", workspace)
		require.NoError(t, ensureWorkspaceDirs(workspace))
		return workspace
	}

	// Create temp directory inside project root
	projectRoot := ".."
	tempRoot := filepath.Join(projectRoot, "test-workspaces")
	if err := os.MkdirAll(tempRoot, 0755); err != nil {
		t.Fatalf("Failed to create test workspaces directory: %v", err)
	}

	// Create a unique temp directory within the project
	tempDir, err := os.MkdirTemp(tempRoot, fmt.Sprintf("test-%s-*", t.Name()))
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	// Register cleanup
	t.Cleanup(func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Failed to clean up temp directory %s: %v", tempDir, err)
		}
	})

	// Copy examples directory to temp workspace
	examplesDir := "../examples"

	// Copy rules directory if it exists
	rulesDir := filepath.Join(examplesDir, "rules")
	if _, err := os.Stat(rulesDir); err == nil {
		destRulesDir := filepath.Join(tempDir, "rules")
		if err := copyDir(rulesDir, destRulesDir); err != nil {
			t.Logf("Warning: failed to copy rules directory: %v", err)
		}
	}

	// Copy mapping files if they exist
	mappingFiles := []string{"mappings.yaml", "custom-mappings.yaml"}
	for _, file := range mappingFiles {
		src := filepath.Join(examplesDir, file)
		if _, err := os.Stat(src); err == nil {
			dst := filepath.Join(tempDir, file)
			if err := copyFile(src, dst); err != nil {
				t.Logf("Warning: failed to copy %s: %v", file, err)
			}
		}
	}

	// Ensure all required directories exist
	require.NoError(t, ensureWorkspaceDirs(tempDir))

	t.Logf("Created temporary workspace: %s", tempDir)
	return tempDir
}

// copyFile copies a single file from src to dst
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

// copyDir recursively copies a directory
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Get relative path
		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		// Create destination path
		dstPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			return os.MkdirAll(dstPath, info.Mode())
		}

		// Copy file
		return copyFile(path, dstPath)
	})
}
