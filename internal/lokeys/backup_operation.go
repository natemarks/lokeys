package lokeys

import "fmt"

// RunBackup creates a timestamped tar backup in secure storage.
func RunBackup() (string, error) {
	return defaultService().RunBackup()
}

// RunBackup creates a timestamped tar backup in secure storage.
func (s *Service) RunBackup() (string, error) {
	vlogf("backup start")
	paths, err := s.appPaths()
	if err != nil {
		return "", err
	}
	cfg, _, err := s.ensureConfig()
	if err != nil {
		return "", fmt.Errorf("ensure config: %w", err)
	}
	key, err := s.deps.Keys.KeyForCommand()
	if err != nil {
		return "", fmt.Errorf("read encryption key: %w", err)
	}
	if err := s.validateKeyForExistingProtectedFiles(cfg, key); err != nil {
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
	backupPath, err := s.createBackupSnapshot(paths)
	if err != nil {
		return "", err
	}
	vlogf("backup complete path=%s", backupPath)
	return backupPath, nil
}

func (s *Service) createBackupSnapshot(paths appPaths) (string, error) {
	return createBackupTarGzWithNow(paths.SecureDir, paths.ConfigPath, s.deps.Now)
}
