package lokeys

import (
	"fmt"
	"os"
)

// AddOptions controls optional behavior for add operations.
type AddOptions struct {
	AllowKMSBypass bool
}

// RunAdd adds a file to protection and replaces it with a RAM-disk symlink.
func RunAdd(pathArg string) error {
	return defaultService().RunAdd(pathArg)
}

// RunAddWithOptions adds a file to protection and replaces it with a RAM-disk symlink.
func RunAddWithOptions(pathArg string, opts AddOptions) error {
	return defaultService().RunAddWithOptions(pathArg, opts)
}

// RunAdd adds a file to protection and replaces it with a RAM-disk symlink.
func (s *Service) RunAdd(pathArg string) error {
	return s.RunAddWithOptions(pathArg, AddOptions{})
}

// RunAddWithOptions adds a file to protection and replaces it with a RAM-disk symlink.
func (s *Service) RunAddWithOptions(pathArg string, opts AddOptions) error {
	vlogf("add start path=%s allow_kms_bypass=%t", pathArg, opts.AllowKMSBypass)
	fullPath, err := expandUserPath(pathArg)
	if err != nil {
		return err
	}

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
	if err := ensureRegularFile(fullPath); err != nil {
		return err
	}

	tracked, fromInsecure, err := trackFileForAdd(paths, fullPath)
	if err != nil {
		return err
	}

	if cfg.hasProtectedFile(tracked.Portable) {
		fmt.Fprintf(s.stdout(), "%s already protected.\n", tracked.Portable)
		return nil
	}
	if fromInsecure && fileExists(tracked.HomePath) {
		return fmt.Errorf("cannot protect RAM-disk file %s: %s", fullPath, ramdiskAddConflictHint(tracked.HomePath, tracked.InsecurePath))
	}
	if opts.AllowKMSBypass && !isAWSCredentialPortablePath(tracked.Portable) {
		return fmt.Errorf("--allow-kms-bypass is only valid for files under $HOME/.aws")
	}
	if shouldUseKMSForPortable(cfg, tracked.Portable) && isAWSCredentialPortablePath(tracked.Portable) {
		if !opts.AllowKMSBypass {
			return fmt.Errorf("cannot protect %s with kms enabled: aws credential dependency loop detected; rerun add with --allow-kms-bypass for this single file", tracked.Portable)
		}
	}
	useKMS := shouldUseKMSForPortable(cfg, tracked.Portable)
	if opts.AllowKMSBypass {
		useKMS = false
	}
	if useKMS {
		if err := ensureKMSReady(cfg); err != nil {
			return err
		}
	}

	p := planAdd(paths, cfg, tracked, fullPath, fromInsecure, key, opts)
	if err := s.applyPlan(p); err != nil {
		return err
	}
	vlogf("add complete path=%s", tracked.Portable)
	return nil
}

func planAdd(paths appPaths, cfg *config, tracked trackedFile, sourcePath string, fromInsecure bool, key []byte, opts AddOptions) plan {
	updated := &config{ProtectedFiles: cfg.protectedFileEntries()}
	if cfg.KMS != nil {
		kms := *cfg.KMS
		updated.KMS = &kms
	}
	updated.KMSBypassFiles = append([]string{}, cfg.KMSBypassFiles...)
	updated.ProtectedFiles = append(updated.ProtectedFiles, protectedFile{Path: tracked.Portable})
	updated.setProtectedFilePaused(tracked.Portable, false)
	if opts.AllowKMSBypass || isAWSAutoBypassPortable(tracked.Portable) {
		updated.KMSBypassFiles = appendUnique(updated.KMSBypassFiles, tracked.Portable)
	}
	useKMS := shouldUseKMSForPortable(cfg, tracked.Portable)
	if opts.AllowKMSBypass {
		useKMS = false
	}
	kmsCfg, _ := cfg.kmsRuntimeConfig()

	actions := []action{
		{Kind: actionEnsureEncryptedDir, Path: paths.SecureDir},
		{Kind: actionEnsureParentDir, Path: tracked.InsecurePath},
		{Kind: actionEnsureParentDir, Path: tracked.SecurePath},
		{Kind: actionEnsureParentDir, Path: tracked.HomePath},
	}
	if !fromInsecure {
		actions = append(actions, action{Kind: actionCopyFile, Source: sourcePath, Path: tracked.InsecurePath, Perm: 0600})
	}
	actions = append(actions,
		action{Kind: actionEncryptFile, Source: tracked.InsecurePath, Path: tracked.SecurePath, Key: key, UseKMS: useKMS, KMS: kmsCfg},
		action{Kind: actionReplaceWithSymlink, Path: tracked.HomePath, Target: tracked.InsecurePath},
		action{Kind: actionWriteConfig, Config: updated},
	)
	return plan{Actions: actions}
}

func trackFileForAdd(paths appPaths, fullPath string) (trackedFile, bool, error) {
	trackedInsecure, fromInsecure, err := buildTrackedFileFromInsecurePath(paths.Home, paths.SecureDir, paths.InsecureDir, fullPath)
	if err != nil {
		return trackedFile{}, false, err
	}
	if fromInsecure {
		return trackedInsecure, true, nil
	}
	trackedHome, err := buildTrackedFileFromHomePath(paths.Home, paths.SecureDir, paths.InsecureDir, fullPath)
	if err != nil {
		return trackedFile{}, false, err
	}
	return trackedHome, false, nil
}

func ramdiskAddConflictHint(homePath string, insecurePath string) string {
	removeHint := fmt.Sprintf("remove this path and retry: rm %q", homePath)
	info, err := os.Lstat(homePath)
	if err != nil {
		return fmt.Sprintf("%s already exists; %s", homePath, removeHint)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(homePath)
		if err != nil {
			return fmt.Sprintf("%s already exists as a symlink; %s", homePath, removeHint)
		}
		if target == insecurePath {
			return fmt.Sprintf("%s already exists as symlink to %s; %s", homePath, insecurePath, removeHint)
		}
		return fmt.Sprintf("%s already exists as symlink to %s; %s", homePath, target, removeHint)
	}
	if info.Mode().IsRegular() {
		return fmt.Sprintf("%s already exists as a regular file; back it up if needed, then %s", homePath, removeHint)
	}
	return fmt.Sprintf("%s already exists; %s", homePath, removeHint)
}
