package lokeys

import (
	"fmt"
	"os"
)

// RunRemove removes a file from protection and cleanup managed copies.
func RunRemove(pathArg string) error {
	return defaultService().RunRemove(pathArg)
}

// RunRemove removes a file from protection and cleanup managed copies.
func (s *Service) RunRemove(pathArg string) error {
	vlogf("remove start path=%s", pathArg)
	fullPath, err := expandUserPath(pathArg)
	if err != nil {
		return err
	}
	portable, err := portablePath(fullPath)
	if err != nil {
		return err
	}

	cfg, _, err := s.ensureConfig()
	if err != nil {
		return fmt.Errorf("ensure config: %w", err)
	}

	idx := -1
	for i, p := range cfg.ProtectedFiles {
		if p == portable {
			idx = i
			break
		}
	}
	if idx == -1 {
		fmt.Fprintf(s.stdout(), "%s is not protected.\n", portable)
		return nil
	}

	paths, err := s.appPaths()
	if err != nil {
		return err
	}
	tracked, err := buildTrackedFileFromHomePath(paths.Home, paths.SecureDir, paths.InsecureDir, fullPath)
	if err != nil {
		return err
	}

	p := planRemove(cfg, idx, tracked)
	if err := s.applyPlan(p); err != nil {
		return err
	}

	fmt.Fprintf(s.stdout(), "removed protection for %s\n", portable)
	vlogf("remove complete path=%s", portable)
	return nil
}

func planRemove(cfg *config, idx int, tracked trackedFile) plan {
	updated := &config{ProtectedFiles: append([]string{}, cfg.ProtectedFiles...)}
	updated.ProtectedFiles = append(updated.ProtectedFiles[:idx], updated.ProtectedFiles[idx+1:]...)
	updated.KMSBypassFiles = make([]string, 0, len(cfg.KMSBypassFiles))
	for _, p := range cfg.KMSBypassFiles {
		if p == tracked.Portable {
			continue
		}
		updated.KMSBypassFiles = append(updated.KMSBypassFiles, p)
	}
	if cfg.KMS != nil {
		kms := *cfg.KMS
		updated.KMS = &kms
	}

	return plan{Actions: []action{
		{Kind: actionRestoreManagedLink, HomePath: tracked.HomePath, InsecurePath: tracked.InsecurePath, SecurePath: tracked.SecurePath},
		{Kind: actionRemovePath, Path: tracked.SecurePath, IgnoreNotExist: true},
		{Kind: actionRemovePath, Path: tracked.InsecurePath, IgnoreNotExist: true},
		{Kind: actionWriteConfig, Config: updated},
	}}
}

func (s *Service) restoreIfManagedSymlink(fullPath string, insecurePath string, securePath string) error {
	info, err := os.Lstat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return nil
	}
	target, err := os.Readlink(fullPath)
	if err != nil {
		return err
	}
	if target != insecurePath {
		return nil
	}

	tmpOut := fullPath + ".lokeys.restore"
	if fileExists(insecurePath) {
		if err := copyFile(insecurePath, tmpOut, 0600); err != nil {
			return err
		}
	} else if fileExists(securePath) {
		key, err := s.deps.Keys.KeyForCommand()
		if err != nil {
			return err
		}
		if err := decryptFile(securePath, tmpOut, key, false, kmsRuntimeConfig{}); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("cannot restore %s: neither insecure nor secure copy exists; recover with `lokeys restore` (or `lokeys restore <archive.tar.gz>`), then retry remove", fullPath)
	}

	if err := removePath(fullPath, false); err != nil {
		return err
	}
	if err := os.Rename(tmpOut, fullPath); err != nil {
		return err
	}
	return nil
}
