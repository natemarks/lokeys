package lokeys

import (
	"fmt"
	"os"
	"path/filepath"
)

type appPaths struct {
	Home        string
	ConfigPath  string
	SecureDir   string
	InsecureDir string
}

func resolveAppPaths() (appPaths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return appPaths{}, fmt.Errorf("resolve user home: %w", err)
	}
	return appPaths{
		Home:        home,
		ConfigPath:  filepath.Join(home, configFileRel),
		SecureDir:   filepath.Join(home, defaultEncryptedRel),
		InsecureDir: filepath.Join(home, defaultDecryptedRel),
	}, nil
}

func (s *Service) appPaths() (appPaths, error) {
	return resolveAppPaths()
}
