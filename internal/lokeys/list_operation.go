package lokeys

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
)

type listStatus string

const (
	statusOK                listStatus = "OK"
	statusMissingInsecure   listStatus = "MISSING_INSECURE"
	statusMissingSecure     listStatus = "MISSING_SECURE"
	statusMismatch          listStatus = "MISMATCH"
	statusUntrackedInsecure listStatus = "UNTRACKED_INSECURE"
)

// RunList lists tracked files and their secure/insecure status.
func RunList() error {
	return defaultService().RunList()
}

// RunList lists tracked files and their secure/insecure status.
func (s *Service) RunList() error {
	vlogf("list start")
	config, created, err := s.ensureConfig()
	if err != nil {
		return fmt.Errorf("ensure config: %w", err)
	}

	paths, err := s.appPaths()
	if err != nil {
		return err
	}
	out := s.stdout()

	if created {
		fmt.Fprintf(out, "No protected files found. Creating config at %s, encrypted storage at %s, and mounting a 100MB RAM disk at %s.\n", paths.ConfigPath, paths.SecureDir, paths.InsecureDir)
		if err := ensureEncryptedDir(paths.SecureDir); err != nil {
			return fmt.Errorf("ensure encrypted dir: %w", err)
		}
		if err := s.deps.Mounter.EnsureMounted(paths.InsecureDir); err != nil {
			return fmt.Errorf("ensure ramdisk mounted: %w", err)
		}
		return nil
	}

	if err := ensureEncryptedDir(paths.SecureDir); err != nil {
		return fmt.Errorf("ensure encrypted dir: %w", err)
	}

	needsKey := false
	for _, entry := range config.ProtectedFiles {
		portable := entry.Path
		tracked, err := buildTrackedFileFromPortable(paths.Home, paths.SecureDir, paths.InsecureDir, portable)
		if err != nil {
			return fmt.Errorf("resolve tracked path %s: %w", portable, err)
		}
		if fileExists(tracked.SecurePath) {
			needsKey = true
			break
		}
	}

	var key []byte
	kmsCfg, _ := config.kmsRuntimeConfig()
	if needsKey {
		key, err = s.deps.Keys.KeyForCommand()
		if err != nil {
			return fmt.Errorf("read encryption key: %w", err)
		}
		if err := s.validateKeyForExistingProtectedFiles(config, key); err != nil {
			return err
		}
		if anyPortableRequiresKMS(config, protectedPaths(config.ProtectedFiles)) {
			if err := ensureKMSReady(config); err != nil {
				return err
			}
		}
	}

	if err := s.deps.Mounter.EnsureMounted(paths.InsecureDir); err != nil {
		return fmt.Errorf("ensure ramdisk mounted: %w", err)
	}

	trackedRels := make(map[string]struct{}, len(config.ProtectedFiles))
	for _, entry := range config.ProtectedFiles {
		portable := entry.Path
		tracked, err := buildTrackedFileFromPortable(paths.Home, paths.SecureDir, paths.InsecureDir, portable)
		if err != nil {
			return fmt.Errorf("resolve tracked path %s: %w", portable, err)
		}
		trackedRels[tracked.Rel] = struct{}{}
	}
	untracked, err := collectUntrackedRamdiskFilesForList(paths, trackedRels)
	if err != nil {
		return err
	}

	if len(config.ProtectedFiles) == 0 && len(untracked) == 0 {
		fmt.Fprintln(out, "No protected files found.")
		return nil
	}

	fmt.Fprintln(out, "Legend: OK=match MISSING_INSECURE=RAM copy missing MISSING_SECURE=encrypted copy missing MISMATCH=hash mismatch")

	for _, entry := range config.ProtectedFiles {
		portable := entry.Path
		tracked, err := buildTrackedFileFromPortable(paths.Home, paths.SecureDir, paths.InsecureDir, portable)
		if err != nil {
			return fmt.Errorf("resolve tracked path %s: %w", portable, err)
		}

		var insecureHash, secureHash string
		insecureExists := fileExists(tracked.InsecurePath)
		secureExists := fileExists(tracked.SecurePath)

		if insecureExists {
			insecureHash, err = sha256File(tracked.InsecurePath)
			if err != nil {
				return fmt.Errorf("hash insecure file %s: %w", tracked.InsecurePath, err)
			}
		}

		if secureExists && key != nil {
			ciphertext, err := os.ReadFile(tracked.SecurePath)
			if err != nil {
				return fmt.Errorf("read secure file %s: %w", tracked.SecurePath, err)
			}
			plaintext, err := decryptBytesWithProfile(ciphertext, key, kmsCfg.Profile)
			if err != nil {
				return fmt.Errorf("decrypt secure file %s: %w", tracked.SecurePath, err)
			}
			secureHash = fmt.Sprintf("%x", sha256.Sum256(plaintext))
		}

		status := statusOK
		switch {
		case !insecureExists:
			status = statusMissingInsecure
		case !secureExists:
			status = statusMissingSecure
		case insecureHash != secureHash:
			status = statusMismatch
		}

		fmt.Fprintf(out, "%s  insecure=%s  secure=%s  %s\n", portable, hashOrMissing(insecureHash), hashOrMissing(secureHash), status)
	}

	for _, tracked := range untracked {
		insecureHash, err := sha256File(tracked.InsecurePath)
		if err != nil {
			return fmt.Errorf("hash untracked insecure file %s: %w", tracked.InsecurePath, err)
		}
		fmt.Fprintf(out, "%s  insecure=%s  secure=MISSING  %s\n", tracked.Portable, hashOrMissing(insecureHash), statusUntrackedInsecure)
	}
	vlogf("list complete tracked=%d untracked=%d", len(config.ProtectedFiles), len(untracked))

	return nil
}

func collectUntrackedRamdiskFilesForList(paths appPaths, trackedRels map[string]struct{}) ([]trackedFile, error) {
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
		portable, err := portablePath(homePath)
		if err != nil {
			return err
		}
		files = append(files, trackedFile{Portable: portable, Rel: rel, HomePath: homePath, InsecurePath: path, SecurePath: filepath.Join(paths.SecureDir, rel)})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("collect untracked insecure files for list: %w", err)
	}
	return files, nil
}

func sha256File(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum), nil
}
