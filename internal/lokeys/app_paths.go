package lokeys

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PathOverrides lets callers provide explicit filesystem locations.
//
// When any of ConfigPath/SecureDir/InsecureDir is set, all three must be set.
type PathOverrides struct {
	Home        string
	ConfigPath  string
	SecureDir   string
	InsecureDir string
}

type appPaths struct {
	Home        string
	ConfigPath  string
	SecureDir   string
	InsecureDir string
}

func resolveAppPaths(overrides PathOverrides) (appPaths, error) {
	home, err := resolveHomeDir(overrides)
	if err != nil {
		return appPaths{}, fmt.Errorf("resolve user home: %w", err)
	}
	configPath, configSet, err := resolvePathOverride(overrides.ConfigPath, ConfigPathEnv)
	if err != nil {
		return appPaths{}, fmt.Errorf("resolve config path: %w", err)
	}
	secureDir, secureSet, err := resolvePathOverride(overrides.SecureDir, SecureDirEnv)
	if err != nil {
		return appPaths{}, fmt.Errorf("resolve secure dir: %w", err)
	}
	insecureDir, insecureSet, err := resolvePathOverride(overrides.InsecureDir, InsecureDirEnv)
	if err != nil {
		return appPaths{}, fmt.Errorf("resolve insecure dir: %w", err)
	}

	anyCustom := configSet || secureSet || insecureSet
	allCustom := configSet && secureSet && insecureSet
	if anyCustom && !allCustom {
		return appPaths{}, fmt.Errorf("when overriding paths, all of %s, %s, and %s must be set", ConfigPathEnv, SecureDirEnv, InsecureDirEnv)
	}

	if !configSet {
		configPath = filepath.Join(home, configFileRel)
	}
	if !secureSet {
		secureDir = filepath.Join(home, defaultEncryptedRel)
	}
	if !insecureSet {
		insecureDir = filepath.Join(home, defaultDecryptedRel)
	}

	resolved := appPaths{
		Home:        home,
		ConfigPath:  configPath,
		SecureDir:   secureDir,
		InsecureDir: insecureDir,
	}
	if !filepath.IsAbs(resolved.ConfigPath) || !filepath.IsAbs(resolved.SecureDir) || !filepath.IsAbs(resolved.InsecureDir) {
		return appPaths{}, fmt.Errorf("resolved paths must be absolute")
	}
	if strings.HasSuffix(resolved.ConfigPath, string(os.PathSeparator)) {
		return appPaths{}, fmt.Errorf("config path must be a file path")
	}
	return resolved, nil
}

func (s *Service) appPaths() (appPaths, error) {
	if s == nil {
		return resolveAppPaths(PathOverrides{})
	}
	return resolveAppPaths(s.deps.Paths)
}

func resolveHomeDir(overrides PathOverrides) (string, error) {
	raw := strings.TrimSpace(overrides.Home)
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv(HomeDirEnv))
	}
	if raw == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Clean(home), nil
	}
	if !filepath.IsAbs(raw) {
		return "", fmt.Errorf("home path must be absolute")
	}
	return filepath.Clean(raw), nil
}

func resolvePathOverride(direct string, envVar string) (string, bool, error) {
	raw := strings.TrimSpace(direct)
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv(envVar))
	}
	if raw == "" {
		return "", false, nil
	}
	if !filepath.IsAbs(raw) {
		return "", false, fmt.Errorf("%s must be an absolute path", envVar)
	}
	return filepath.Clean(raw), true, nil
}
