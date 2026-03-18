package lokeys

import "fmt"

// RunRotate rotates encrypted storage from old key to a new key.
func RunRotate() (string, int, error) {
	return defaultService().RunRotate()
}

// RunRotate rotates encrypted storage from old key to a new key.
func (s *Service) RunRotate() (string, int, error) {
	cfg, _, err := ensureConfig()
	if err != nil {
		return "", 0, fmt.Errorf("ensure config: %w", err)
	}

	oldKey, fromEnv, err := s.deps.Keys.KeyFromSessionEnv()
	if err != nil {
		return "", 0, fmt.Errorf("read session key: %w", err)
	}
	if !fromEnv {
		oldKey, _, err = s.deps.Keys.PromptForKey()
		if err != nil {
			return "", 0, fmt.Errorf("prompt for old key: %w", err)
		}
	}
	if err := validateKeyForExistingProtectedFiles(cfg, oldKey); err != nil {
		return "", 0, err
	}

	paths, err := s.appPaths()
	if err != nil {
		return "", 0, err
	}

	if err := ensureEncryptedDir(paths.SecureDir); err != nil {
		return "", 0, fmt.Errorf("ensure encrypted dir: %w", err)
	}
	if err := s.deps.Mounter.EnsureMounted(paths.InsecureDir); err != nil {
		return "", 0, fmt.Errorf("ensure ramdisk mounted: %w", err)
	}

	if err := sealTrackedFromRamdisk(cfg, paths, oldKey); err != nil {
		return "", 0, err
	}
	updatedCfg, err := s.sealTrackedAndDiscovered(cfg, paths, oldKey)
	if err != nil {
		return "", 0, err
	}

	backupPath, err := s.createBackupSnapshot(paths)
	if err != nil {
		return "", 0, err
	}

	newKey, _, err := s.deps.Keys.PromptForNewKey()
	if err != nil {
		return "", 0, fmt.Errorf("prompt for new key: %w", err)
	}
	if keysEqual(oldKey, newKey) {
		return "", 0, fmt.Errorf("new encryption key must differ from existing key")
	}

	plans, err := buildRotationPlans(updatedCfg, paths, oldKey, newKey)
	if err != nil {
		cleanupRotationTempFiles(plans)
		return backupPath, 0, err
	}

	rotated, err := applyRotationPlans(plans)
	if err != nil {
		cleanupRotationTempFiles(plans)
		return backupPath, 0, err
	}

	return backupPath, rotated, nil
}
