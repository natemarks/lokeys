package lokeys

import "fmt"

// RunAdd adds a file to protection and replaces it with a RAM-disk symlink.
func RunAdd(pathArg string) error {
	return defaultService().RunAdd(pathArg)
}

// RunAdd adds a file to protection and replaces it with a RAM-disk symlink.
func (s *Service) RunAdd(pathArg string) error {
	fullPath, err := expandUserPath(pathArg)
	if err != nil {
		return err
	}

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

	if containsString(cfg.ProtectedFiles, tracked.Portable) {
		fmt.Fprintf(s.stdout(), "%s already protected.\n", tracked.Portable)
		return nil
	}
	if fromInsecure && fileExists(tracked.HomePath) {
		return fmt.Errorf("cannot protect RAM-disk file %s: %s already exists", fullPath, tracked.HomePath)
	}

	p := planAdd(paths, cfg, tracked, fullPath, fromInsecure, key)
	if err := s.applyPlan(p); err != nil {
		return err
	}
	return nil
}

func planAdd(paths appPaths, cfg *config, tracked trackedFile, sourcePath string, fromInsecure bool, key []byte) plan {
	updated := &config{ProtectedFiles: append([]string{}, cfg.ProtectedFiles...)}
	updated.ProtectedFiles = append(updated.ProtectedFiles, tracked.Portable)

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
		action{Kind: actionEncryptFile, Source: tracked.InsecurePath, Path: tracked.SecurePath, Key: key},
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
