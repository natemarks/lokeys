package lokeys

import "fmt"

// RunUnseal decrypts all tracked files into RAM-disk storage.
func RunUnseal() error {
	return defaultService().RunUnseal()
}

// RunUnseal decrypts all tracked files into RAM-disk storage.
func (s *Service) RunUnseal() error {
	vlogf("unseal start")
	cfg, _, err := s.ensureConfig()
	if err != nil {
		return fmt.Errorf("ensure config: %w", err)
	}
	key, err := s.deps.Keys.KeyForCommand()
	if err != nil {
		return fmt.Errorf("read encryption key: %w", err)
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
	localTracked, kmsTracked := partitionTrackedByKMS(cfg, tracked)
	awsSeeded := hasAWSAutoBypassTracked(localTracked)

	if len(localTracked) > 0 {
		if err := s.applyPlan(planUnseal(cfg, localTracked, key)); err != nil {
			return err
		}
	}
	if len(kmsTracked) == 0 {
		vlogf("unseal complete files=%d", len(tracked))
		return nil
	}
	if err := ensureKMSReady(cfg); err != nil {
		if awsSeeded {
			return fmt.Errorf("%w: decrypted local-key files (including .aws), but KMS-protected files could not be decrypted yet; run `lokeys unseal` again", err)
		}
		return err
	}

	if err := s.applyPlan(planUnseal(cfg, kmsTracked, key)); err != nil {
		if awsSeeded && isKMSError(err) {
			return fmt.Errorf("%w: decrypted local-key files (including .aws), but KMS-protected files could not be decrypted yet; run `lokeys unseal` again", err)
		}
		return err
	}
	vlogf("unseal complete files=%d", len(tracked))
	return nil
}

func partitionTrackedByKMS(cfg *config, tracked []trackedFile) ([]trackedFile, []trackedFile) {
	local := make([]trackedFile, 0, len(tracked))
	kms := make([]trackedFile, 0, len(tracked))
	for _, tf := range tracked {
		if shouldUseKMSForPortable(cfg, tf.Portable) {
			kms = append(kms, tf)
			continue
		}
		local = append(local, tf)
	}
	return local, kms
}

func hasAWSAutoBypassTracked(tracked []trackedFile) bool {
	for _, tf := range tracked {
		if isAWSAutoBypassPortable(tf.Portable) {
			return true
		}
	}
	return false
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
