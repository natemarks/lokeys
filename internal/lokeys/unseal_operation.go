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

	tracked, err := collectUnsealTracked(paths, cfg)
	if err != nil {
		return err
	}
	execPlan := planUnsealExecution(cfg, tracked, key)

	if len(execPlan.LocalTracked) > 0 {
		if err := s.applyPlan(execPlan.LocalPlan); err != nil {
			return err
		}
	}
	if len(execPlan.KMSTracked) == 0 {
		vlogf("unseal complete files=%d", len(execPlan.AllTracked))
		return nil
	}
	if err := ensureKMSReady(cfg); err != nil {
		if execPlan.AWSSeededLocal {
			return fmt.Errorf("%w: decrypted local-key files (including .aws), but KMS-protected files could not be decrypted yet; run `lokeys unseal` again", err)
		}
		return err
	}

	if err := s.applyPlan(execPlan.KMSPlan); err != nil {
		if execPlan.AWSSeededLocal && isKMSError(err) {
			return fmt.Errorf("%w: decrypted local-key files (including .aws), but KMS-protected files could not be decrypted yet; run `lokeys unseal` again", err)
		}
		return err
	}
	vlogf("unseal complete files=%d", len(execPlan.AllTracked))
	return nil
}

func collectUnsealTracked(paths appPaths, cfg *config) ([]trackedFile, error) {
	tracked := make([]trackedFile, 0, len(cfg.ProtectedFiles))
	for _, entry := range cfg.ProtectedFiles {
		if entry.Paused {
			continue
		}
		portable := entry.Path
		tf, err := buildTrackedFileFromPortable(paths.Home, paths.SecureDir, paths.InsecureDir, portable)
		if err != nil {
			return nil, fmt.Errorf("resolve tracked path %s: %w", portable, err)
		}
		tracked = append(tracked, tf)
	}
	return tracked, nil
}

type unsealExecutionPlan struct {
	AllTracked     []trackedFile
	LocalTracked   []trackedFile
	KMSTracked     []trackedFile
	LocalPlan      plan
	KMSPlan        plan
	AWSSeededLocal bool
}

func planUnsealExecution(cfg *config, tracked []trackedFile, key []byte) unsealExecutionPlan {
	localTracked, kmsTracked := partitionTrackedByKMS(cfg, tracked)
	return unsealExecutionPlan{
		AllTracked:     tracked,
		LocalTracked:   localTracked,
		KMSTracked:     kmsTracked,
		LocalPlan:      planUnseal(cfg, localTracked, key),
		KMSPlan:        planUnseal(cfg, kmsTracked, key),
		AWSSeededLocal: hasAWSAutoBypassTracked(localTracked),
	}
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
	// Invariant: all tracked inputs are already filtered for eligibility by the
	// caller (for example paused entries are removed before this planner runs).
	// This planner always emits decrypt+symlink actions for each provided file.
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
