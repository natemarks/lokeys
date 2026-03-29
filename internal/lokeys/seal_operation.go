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

	if _, err := s.sealTrackedAndDiscovered(cfg, paths, key, opts); err != nil {
		return err
	}
	vlogf("seal complete")
	return nil
}

func (s *Service) sealTrackedAndDiscovered(cfg *config, paths appPaths, key []byte, opts SealOptions) (*config, error) {
	vlogf("seal tracked=%d", len(cfg.ProtectedFiles))
	trackedRels := make(map[string]struct{}, len(cfg.ProtectedFiles))
	trackedFiles := make([]trackedFile, 0, len(cfg.ProtectedFiles))
	for _, entry := range cfg.ProtectedFiles {
		portable := entry.Path
		tracked, err := buildTrackedFileFromPortable(paths.Home, paths.SecureDir, paths.InsecureDir, portable)
		if err != nil {
			return nil, fmt.Errorf("resolve tracked path %s: %w", portable, err)
		}
		trackedRels[tracked.Rel] = struct{}{}
		trackedFiles = append(trackedFiles, tracked)
	}

	discovered, err := collectUntrackedRamdiskFiles(paths, trackedRels)
	if err != nil {
		return nil, err
	}
	vlogf("seal discovered_untracked=%d", len(discovered))

	allowBypass := map[string]struct{}{}
	for _, raw := range opts.AllowKMSBypassFiles {
		normalized, err := normalizePortableBypassInput(raw)
		if err != nil {
			return nil, err
		}
		allowBypass[normalized] = struct{}{}
	}
	if _, enabled := cfg.kmsRuntimeConfig(); enabled {
		blocked := []string{}
		requiresKMS := anyPortableRequiresKMS(cfg, cfg.protectedFilePaths())
		for _, tf := range discovered {
			if !isAWSCredentialPortablePath(tf.Portable) {
				requiresKMS = true
				continue
			}
			if isAWSAutoBypassPortable(tf.Portable) {
				continue
			}
			if _, ok := allowBypass[tf.Portable]; ok {
				continue
			}
			blocked = append(blocked, tf.Portable)
		}
		if len(blocked) > 0 {
			return nil, fmt.Errorf("kms is enabled; refusing to auto-protect AWS credential files without explicit bypass: %s; rerun with --allow-kms-bypass-file for each file", strings.Join(blocked, ", "))
		}
		if requiresKMS {
			if err := ensureKMSReady(cfg); err != nil {
				return nil, err
			}
		}
	}

	p, updated := planSeal(paths, cfg, trackedFiles, discovered, key, allowBypass)
	if err := s.applyPlan(p); err != nil {
		return nil, err
	}
	return updated, nil
}

func planSeal(paths appPaths, cfg *config, tracked []trackedFile, discovered []trackedFile, key []byte, allowBypass map[string]struct{}) (plan, *config) {
	actions := []action{{Kind: actionEnsureEncryptedDir, Path: paths.SecureDir}}
	kmsCfg, _ := cfg.kmsRuntimeConfig()
	for _, tf := range tracked {
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
