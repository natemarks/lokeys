package lokeys

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SealOptions controls optional behavior for seal operations.
type SealOptions struct {
	AllowKMSBypassFiles []string
}

// RunSeal encrypts all tracked RAM-disk files into secure storage.
func RunSeal() error {
	return defaultService().RunSeal()
}

// RunSealWithOptions encrypts all tracked RAM-disk files into secure storage.
func RunSealWithOptions(opts SealOptions) error {
	return defaultService().RunSealWithOptions(opts)
}

// RunSeal encrypts all tracked RAM-disk files into secure storage.
func (s *Service) RunSeal() error {
	return s.RunSealWithOptions(SealOptions{})
}

// RunSealWithOptions encrypts all tracked RAM-disk files into secure storage.
func (s *Service) RunSealWithOptions(opts SealOptions) error {
	vlogf("seal start allow_kms_bypass_files=%d", len(opts.AllowKMSBypassFiles))
	cfg, _, err := s.ensureConfig()
	if err != nil {
		return fmt.Errorf("ensure config: %w", err)
	}
	key, err := s.deps.Keys.KeyForCommand()
	if err != nil {
		return fmt.Errorf("read encryption key: %w", err)
	}
	if err := s.validateKeyForExistingProtectedFiles(cfg, key); err != nil {
		return err
	}

	paths, err := s.appPaths()
	if err != nil {
		return err
	}
	if err := s.deps.Mounter.EnsureMounted(paths.InsecureDir); err != nil {
		return fmt.Errorf("ensure ramdisk mounted: %w", err)
	}

	input, err := collectSealPlanInput(paths, cfg, opts)
	if err != nil {
		return err
	}
	if _, err := s.sealWithPlanInput(input, key); err != nil {
		return err
	}
	vlogf("seal complete")
	return nil
}

func (s *Service) sealWithPlanInput(input sealPlanInput, key []byte) (*config, error) {
	vlogf("seal tracked=%d", len(input.Tracked))
	vlogf("seal discovered_untracked=%d", len(input.Discovered))

	if _, enabled := input.Config.kmsRuntimeConfig(); enabled {
		kmsDecision := decideSealKMSPolicy(input.Config, input.TrackedExistingInsecure, input.Discovered, input.AllowBypass)
		if len(kmsDecision.BlockedBypass) > 0 {
			return nil, fmt.Errorf("kms is enabled; refusing to auto-protect AWS credential files without explicit bypass: %s; rerun with --allow-kms-bypass-file for each file", strings.Join(kmsDecision.BlockedBypass, ", "))
		}
		if kmsDecision.RequiresKMS {
			if err := ensureKMSReady(input.Config); err != nil {
				return nil, err
			}
		}
	}

	p, updated := planSeal(input.Paths, input.Config, input.Tracked, input.Discovered, key, input.AllowBypass)
	if err := s.applyPlan(p); err != nil {
		return nil, err
	}
	return updated, nil
}

func (s *Service) sealTrackedAndDiscovered(cfg *config, paths appPaths, key []byte, opts SealOptions) (*config, error) {
	input, err := collectSealPlanInput(paths, cfg, opts)
	if err != nil {
		return nil, err
	}
	return s.sealWithPlanInput(input, key)
}

type sealPlanInput struct {
	Paths                   appPaths
	Config                  *config
	Tracked                 []trackedFile
	TrackedExistingInsecure []trackedFile
	Discovered              []trackedFile
	AllowBypass             map[string]struct{}
}

func collectSealPlanInput(paths appPaths, cfg *config, opts SealOptions) (sealPlanInput, error) {
	trackedRels := make(map[string]struct{}, len(cfg.ProtectedFiles))
	trackedFiles := make([]trackedFile, 0, len(cfg.ProtectedFiles))
	trackedExistingInsecure := make([]trackedFile, 0, len(cfg.ProtectedFiles))
	for _, entry := range cfg.ProtectedFiles {
		portable := entry.Path
		tracked, err := buildTrackedFileFromPortable(paths.Home, paths.SecureDir, paths.InsecureDir, portable)
		if err != nil {
			return sealPlanInput{}, fmt.Errorf("resolve tracked path %s: %w", portable, err)
		}
		trackedRels[tracked.Rel] = struct{}{}
		trackedFiles = append(trackedFiles, tracked)
		if fileExists(tracked.InsecurePath) {
			trackedExistingInsecure = append(trackedExistingInsecure, tracked)
		}
	}

	discovered, err := collectUntrackedRamdiskFiles(paths, trackedRels)
	if err != nil {
		return sealPlanInput{}, err
	}

	allowBypass := map[string]struct{}{}
	for _, raw := range opts.AllowKMSBypassFiles {
		normalized, err := normalizePortableBypassInput(raw)
		if err != nil {
			return sealPlanInput{}, err
		}
		allowBypass[normalized] = struct{}{}
	}

	return sealPlanInput{
		Paths:                   paths,
		Config:                  cfg,
		Tracked:                 trackedFiles,
		TrackedExistingInsecure: trackedExistingInsecure,
		Discovered:              discovered,
		AllowBypass:             allowBypass,
	}, nil
}

type sealKMSDecision struct {
	RequiresKMS   bool
	BlockedBypass []string
}

func decideSealKMSPolicy(cfg *config, trackedExistingInsecure []trackedFile, discovered []trackedFile, allowBypass map[string]struct{}) sealKMSDecision {
	decision := sealKMSDecision{}
	for _, tf := range trackedExistingInsecure {
		if shouldUseKMSForPortable(cfg, tf.Portable) {
			decision.RequiresKMS = true
			break
		}
	}

	for _, tf := range discovered {
		if !isAWSCredentialPortablePath(tf.Portable) {
			decision.RequiresKMS = true
			continue
		}
		if isAWSAutoBypassPortable(tf.Portable) {
			continue
		}
		if _, ok := allowBypass[tf.Portable]; ok {
			continue
		}
		decision.BlockedBypass = append(decision.BlockedBypass, tf.Portable)
	}
	return decision
}

func planSeal(paths appPaths, cfg *config, tracked []trackedFile, discovered []trackedFile, key []byte, allowBypass map[string]struct{}) (plan, *config) {
	// Invariants for tracked files:
	// - Missing insecure sources are non-fatal and skipped.
	// - No config mutation occurs for tracked-only sealing.
	// Invariants for discovered files:
	// - Enrollment is explicit in this planner and always paired with a config
	//   write action.
	// - KMS bypass decisions are persisted via updated.KMSBypassFiles.
	actions := []action{{Kind: actionEnsureEncryptedDir, Path: paths.SecureDir}}
	kmsCfg, _ := cfg.kmsRuntimeConfig()
	for _, tf := range tracked {
		if !fileExists(tf.InsecurePath) {
			continue
		}
		useKMS := shouldUseKMSForPortable(cfg, tf.Portable)
		actions = append(actions,
			action{Kind: actionEnsureParentDir, Path: tf.SecurePath},
			action{Kind: actionEncryptFile, Source: tf.InsecurePath, Path: tf.SecurePath, Key: key, UseKMS: useKMS, KMS: kmsCfg},
		)
	}

	updated := cfg
	if len(discovered) > 0 {
		updated = &config{ProtectedFiles: cfg.protectedFileEntries()}
		updated.KMSBypassFiles = append([]string{}, cfg.KMSBypassFiles...)
		if cfg.KMS != nil {
			kms := *cfg.KMS
			updated.KMS = &kms
		}
		for _, tf := range discovered {
			_, bypassedByFlag := allowBypass[tf.Portable]
			bypassed := bypassedByFlag || isAWSAutoBypassPortable(tf.Portable)
			if bypassed {
				updated.KMSBypassFiles = appendUnique(updated.KMSBypassFiles, tf.Portable)
			}
			useKMS := shouldUseKMSForPortable(updated, tf.Portable)
			actions = append(actions,
				action{Kind: actionEnsureParentDir, Path: tf.SecurePath},
				action{Kind: actionEnsureParentDir, Path: tf.HomePath},
				action{Kind: actionEncryptFile, Source: tf.InsecurePath, Path: tf.SecurePath, Key: key, UseKMS: useKMS, KMS: kmsCfg},
				action{Kind: actionReplaceWithSymlink, Path: tf.HomePath, Target: tf.InsecurePath},
			)
			updated.ProtectedFiles = append(updated.ProtectedFiles, protectedFile{Path: tf.Portable})
		}
		actions = append(actions, action{Kind: actionWriteConfig, Config: updated})
	}

	return plan{Actions: actions}, updated
}

func normalizePortableBypassInput(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("empty --allow-kms-bypass-file value")
	}
	if strings.HasPrefix(raw, "$HOME") {
		if !isAWSCredentialPortablePath(raw) {
			return "", fmt.Errorf("--allow-kms-bypass-file only accepts $HOME/.aws/* paths")
		}
		return raw, nil
	}
	full, err := expandUserPath(raw)
	if err != nil {
		return "", err
	}
	portable, err := portablePath(full)
	if err != nil {
		return "", err
	}
	if !isAWSCredentialPortablePath(portable) {
		return "", fmt.Errorf("--allow-kms-bypass-file only accepts $HOME/.aws/* paths")
	}
	return portable, nil
}

func collectUntrackedRamdiskFiles(paths appPaths, trackedRels map[string]struct{}) ([]trackedFile, error) {
	files := []trackedFile{}
	err := filepath.WalkDir(paths.InsecureDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		rel, err := relToBase(paths.InsecureDir, path)
		if err != nil {
			return err
		}
		if _, tracked := trackedRels[rel]; tracked {
			return nil
		}
		homePath := homePathFromInsecureRel(paths.Home, rel)
		if fileExists(homePath) {
			return fmt.Errorf("refusing to seal RAM-disk file %s: %s already exists; remove or move the existing home path and retry (example: rm %q)", path, homePath, homePath)
		}
		portable, err := portablePath(homePath)
		if err != nil {
			return err
		}
		files = append(files, trackedFile{Portable: portable, Rel: rel, HomePath: homePath, InsecurePath: path, SecurePath: filepath.Join(paths.SecureDir, rel)})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("collect untracked ramdisk files: %w", err)
	}
	return files, nil
}
