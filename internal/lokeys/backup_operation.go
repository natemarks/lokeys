package lokeys

import "fmt"

// RunBackup creates a timestamped tar backup in secure storage.
func RunBackup() (string, error) {
	return defaultService().RunBackup()
}

// RunBackup creates a timestamped tar backup in secure storage.
func (s *Service) RunBackup() (string, error) {
	paths, err := s.appPaths()
	if err != nil {
		return "", err
	}
	cfg, _, err := ensureConfig()
	if err != nil {
		return "", fmt.Errorf("ensure config: %w", err)
	}
	key, err := s.deps.Keys.KeyForCommand()
	if err != nil {
		return "", fmt.Errorf("read encryption key: %w", err)
	}
	if err := validateKeyForExistingProtectedFiles(cfg, key); err != nil {
		return "", err
	}
	if anyPortableRequiresKMS(cfg, cfg.ProtectedFiles) {
		if err := ensureKMSReady(cfg); err != nil {
			return "", err
		}
	}
	if err := s.deps.Mounter.EnsureMounted(paths.InsecureDir); err != nil {
		return "", fmt.Errorf("ensure ramdisk mounted: %w", err)
	}
	if _, err := s.sealTrackedAndDiscovered(cfg, paths, key, SealOptions{}); err != nil {
		return "", err
	}
	return s.createBackupSnapshot(paths)
}

func (s *Service) createBackupSnapshot(paths appPaths) (string, error) {
	return createBackupTarGzWithNow(paths.SecureDir, paths.ConfigPath, s.deps.Now)
}
