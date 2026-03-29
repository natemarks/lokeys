package lokeys

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type configJSON struct {
	ProtectedFiles json.RawMessage `json:"protectedFiles"`
	KMS            *kmsConfig      `json:"kms,omitempty"`
	KMSBypassFiles []string        `json:"kmsBypassFiles,omitempty"`
}

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

	cfg := &config{ProtectedFiles: []protectedFile{}}
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
	var raw configJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	cfg := &config{
		KMS:            raw.KMS,
		KMSBypassFiles: raw.KMSBypassFiles,
	}
	if len(raw.ProtectedFiles) == 0 || string(raw.ProtectedFiles) == "null" {
		cfg.ProtectedFiles = []protectedFile{}
		return cfg, nil
	}

	var entries []protectedFile
	if err := json.Unmarshal(raw.ProtectedFiles, &entries); err == nil {
		cfg.ProtectedFiles = entries
		return cfg, nil
	}

	var legacy []string
	if err := json.Unmarshal(raw.ProtectedFiles, &legacy); err != nil {
		return nil, err
	}
	cfg.ProtectedFiles = make([]protectedFile, 0, len(legacy))
	for _, path := range legacy {
		cfg.ProtectedFiles = append(cfg.ProtectedFiles, protectedFile{Path: path, Paused: false})
	}
	return cfg, nil
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
