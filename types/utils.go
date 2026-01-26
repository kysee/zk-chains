package types

import (
	"fmt"
	"os"
	"path/filepath"
)

// ProjectRoot finds the project root directory by searching for go.mod file
// starting from the given startPath (default: current directory)
func ProjectRoot(startPath ...string) (string, error) {
	start := "."
	if len(startPath) > 0 {
		start = startPath[0]
	}

	// Convert to absolute path
	currentPath, err := filepath.Abs(start)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Walk up directory tree until we find go.mod
	for {
		// Check if go.mod exists in current directory
		goModPath := filepath.Join(currentPath, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			//fmt.Println("found project root dir:", currentPath)
			return currentPath, nil
		}

		// Get parent directory
		parentPath := filepath.Dir(currentPath)

		// Check if we've reached the root
		if parentPath == currentPath {
			return "", fmt.Errorf("not found project root dir")
		}

		currentPath = parentPath
		//fmt.Println("next dir:", currentPath)
	}
}
