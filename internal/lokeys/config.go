package lokeys

import (
	"encoding/json"
	"os"
	"path/filepath"
)

func ensureConfig() (*config, bool, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, false, err
	}
	path := filepath.Join(home, configFileRel)
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
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(home, configFileRel)
	return writeConfigTo(path, cfg)
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
	return os.WriteFile(path, data, configFilePerm)
}
