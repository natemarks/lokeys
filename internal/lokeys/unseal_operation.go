package lokeys

import "fmt"

// RunUnseal decrypts all tracked files into RAM-disk storage.
func RunUnseal() error {
	return defaultService().RunUnseal()
}

// RunUnseal decrypts all tracked files into RAM-disk storage.
func (s *Service) RunUnseal() error {
	cfg, _, err := ensureConfig()
	if err != nil {
		return fmt.Errorf("ensure config: %w", err)
	}
	key, err := s.deps.Keys.KeyForCommand()
	if err != nil {
		return fmt.Errorf("read encryption key: %w", err)
	}
	if err := validateKeyForExistingProtectedFiles(cfg, key); err != nil {
		return err
	}
	if anyPortableRequiresKMS(cfg, cfg.ProtectedFiles) {
		if err := ensureKMSReady(cfg); err != nil {
			return err
		}
	}

	paths, err := s.appPaths()
	if err != nil {
		return err
	}
	if err := s.deps.Mounter.EnsureMounted(paths.InsecureDir); err != nil {
		return fmt.Errorf("ensure ramdisk mounted: %w", err)
	}

	tracked := make([]trackedFile, 0, len(cfg.ProtectedFiles))
	for _, portable := range cfg.ProtectedFiles {
		tf, err := buildTrackedFileFromPortable(paths.Home, paths.SecureDir, paths.InsecureDir, portable)
		if err != nil {
			return fmt.Errorf("resolve tracked path %s: %w", portable, err)
		}
		tracked = append(tracked, tf)
	}

	p := planUnseal(cfg, tracked, key)
	if err := s.applyPlan(p); err != nil {
		return err
	}
	return nil
}

func planUnseal(cfg *config, tracked []trackedFile, key []byte) plan {
	kmsCfg, _ := cfg.kmsRuntimeConfig()
	actions := make([]action, 0, len(tracked)*3)
	for _, tf := range tracked {
		useKMS := shouldUseKMSForPortable(cfg, tf.Portable)
		actions = append(actions,
			action{Kind: actionEnsureParentDir, Path: tf.InsecurePath},
			action{Kind: actionDecryptFile, Source: tf.SecurePath, Path: tf.InsecurePath, Key: key, UseKMS: useKMS, KMS: kmsCfg},
			action{Kind: actionReplaceWithSymlink, Path: tf.HomePath, Target: tf.InsecurePath},
		)
	}
	return plan{Actions: actions}
}
