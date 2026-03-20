package lokeys

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func ensureConfig() (*config, bool, error) {
	paths, err := resolveAppPaths(PathOverrides{})
	if err != nil {
		return nil, false, err
	}
	return ensureConfigAt(paths.ConfigPath)
}

func (s *Service) ensureConfig() (*config, bool, error) {
	if s == nil {
		return ensureConfig()
	}
	paths, err := s.appPaths()
	if err != nil {
		return nil, false, err
	}
	return ensureConfigAt(paths.ConfigPath)
}

func ensureConfigAt(path string) (*config, bool, error) {
	_, statErr := os.Stat(path)
	if statErr == nil {
		cfg, err := readConfig(path)
		return cfg, false, err
	}
	if !os.IsNotExist(statErr) {
		return nil, false, statErr
	}

	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return nil, false, err
	}

	cfg := &config{ProtectedFiles: []string{}}
	if err := writeConfigTo(path, cfg); err != nil {
		return nil, false, err
	}
	return cfg, true, nil
}

func writeConfig(cfg *config) error {
	paths, err := resolveAppPaths(PathOverrides{})
	if err != nil {
		return err
	}
	return writeConfigTo(paths.ConfigPath, cfg)
}

func (s *Service) writeConfig(cfg *config) error {
	if s == nil {
		return writeConfig(cfg)
	}
	paths, err := s.appPaths()
	if err != nil {
		return err
	}
	return writeConfigTo(paths.ConfigPath, cfg)
}

func readConfig(path string) (*config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func writeConfigTo(path string, cfg *config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if err := tmp.Chmod(configFilePerm); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("atomic replace config: %w", err)
	}
	return nil
}
