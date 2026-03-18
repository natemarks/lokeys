package lokeys

import (
	"fmt"
	"os"
	"path/filepath"
)

// RunSeal encrypts all tracked RAM-disk files into secure storage.
func RunSeal() error {
	return defaultService().RunSeal()
}

// RunSeal encrypts all tracked RAM-disk files into secure storage.
func (s *Service) RunSeal() error {
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

	if _, err := s.sealTrackedAndDiscovered(cfg, paths, key); err != nil {
		return err
	}
	return nil
}

func (s *Service) sealTrackedAndDiscovered(cfg *config, paths appPaths, key []byte) (*config, error) {
	trackedRels := make(map[string]struct{}, len(cfg.ProtectedFiles))
	trackedFiles := make([]trackedFile, 0, len(cfg.ProtectedFiles))
	for _, portable := range cfg.ProtectedFiles {
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

	p, updated := planSeal(paths, cfg, trackedFiles, discovered, key)
	if err := s.applyPlan(p); err != nil {
		return nil, err
	}
	return updated, nil
}

func planSeal(paths appPaths, cfg *config, tracked []trackedFile, discovered []trackedFile, key []byte) (plan, *config) {
	actions := []action{{Kind: actionEnsureEncryptedDir, Path: paths.SecureDir}}
	for _, tf := range tracked {
		actions = append(actions,
			action{Kind: actionEnsureParentDir, Path: tf.SecurePath},
			action{Kind: actionEncryptFile, Source: tf.InsecurePath, Path: tf.SecurePath, Key: key},
		)
	}

	updated := cfg
	if len(discovered) > 0 {
		updated = &config{ProtectedFiles: append([]string{}, cfg.ProtectedFiles...)}
		for _, tf := range discovered {
			actions = append(actions,
				action{Kind: actionEnsureParentDir, Path: tf.SecurePath},
				action{Kind: actionEnsureParentDir, Path: tf.HomePath},
				action{Kind: actionEncryptFile, Source: tf.InsecurePath, Path: tf.SecurePath, Key: key},
				action{Kind: actionReplaceWithSymlink, Path: tf.HomePath, Target: tf.InsecurePath},
			)
			updated.ProtectedFiles = append(updated.ProtectedFiles, tf.Portable)
		}
		actions = append(actions, action{Kind: actionWriteConfig, Config: updated})
	}

	return plan{Actions: actions}, updated
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
			return fmt.Errorf("refusing to seal RAM-disk file %s: %s already exists", path, homePath)
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
