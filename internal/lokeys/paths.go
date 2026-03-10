package lokeys

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func expandUserPath(path string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if path == "~" {
		path = home
	} else if strings.HasPrefix(path, "~/") {
		path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
	}
	path = os.ExpandEnv(path)
	if !filepath.IsAbs(path) {
		path, err = filepath.Abs(path)
		if err != nil {
			return "", err
		}
	}
	return filepath.Clean(path), nil
}

func portablePath(path string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	path = filepath.Clean(path)
	if !strings.HasPrefix(path, home+string(os.PathSeparator)) && path != home {
		return "", fmt.Errorf("path must be under $HOME")
	}
	if path == home {
		return "$HOME", nil
	}
	return strings.Replace(path, home, "$HOME", 1), nil
}

func expandPortablePath(path string) (string, error) {
	if strings.HasPrefix(path, "$HOME") {
		return expandUserPath(strings.Replace(path, "$HOME", "~", 1))
	}
	return expandUserPath(path)
}

func relToHome(path string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(home, path)
	if err != nil {
		return "", err
	}
	if rel == "." || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("path must be under $HOME")
	}
	return rel, nil
}
