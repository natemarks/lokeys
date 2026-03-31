package lokeys

import (
	"crypto/sha256"
	"fmt"
	"io"
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
	cfg, created, err := s.ensureConfig()
	if err != nil {
		return fmt.Errorf("ensure config: %w", err)
	}

	paths, err := s.appPaths()
	if err != nil {
		return err
	}
	out := s.stdout()

	if created {
		return s.runListCreatedConfig(paths)
	}
	return s.runListExistingConfig(cfg, paths, out)
}

func (s *Service) runListCreatedConfig(paths appPaths) error {
	fmt.Fprintf(s.stdout(), "No protected files found. Creating config at %s, encrypted storage at %s, and mounting a 100MB RAM disk at %s.\n", paths.ConfigPath, paths.SecureDir, paths.InsecureDir)
	if err := ensureEncryptedDir(paths.SecureDir); err != nil {
		return fmt.Errorf("ensure encrypted dir: %w", err)
	}
	if err := s.deps.Mounter.EnsureMounted(paths.InsecureDir); err != nil {
		return fmt.Errorf("ensure ramdisk mounted: %w", err)
	}
	return nil
}

func (s *Service) runListExistingConfig(cfg *config, paths appPaths, out io.Writer) error {
	trackedEntries, trackedRels, err := collectListTrackedEntries(paths, cfg)
	if err != nil {
		return err
	}

	if err := ensureEncryptedDir(paths.SecureDir); err != nil {
		return fmt.Errorf("ensure encrypted dir: %w", err)
	}

	var key []byte
	kmsCfg, _ := cfg.kmsRuntimeConfig()
	if needsListKey(trackedEntries) {
		key, err = s.deps.Keys.KeyForCommand()
		if err != nil {
			return fmt.Errorf("read encryption key: %w", err)
		}
		if err := s.validateKeyForExistingProtectedFiles(cfg, key); err != nil {
			return err
		}
		if anyPortableRequiresKMS(cfg, cfg.protectedFilePaths()) {
			if err := ensureKMSReady(cfg); err != nil {
				return err
			}
		}
	}

	if err := s.deps.Mounter.EnsureMounted(paths.InsecureDir); err != nil {
		return fmt.Errorf("ensure ramdisk mounted: %w", err)
	}

	untracked, err := collectUntrackedRamdiskFilesForList(paths, trackedRels)
	if err != nil {
		return err
	}

	if len(trackedEntries) == 0 && len(untracked) == 0 {
		fmt.Fprintln(out, "No protected files found.")
		return nil
	}

	fmt.Fprintln(out, "Legend: OK=match MISSING_INSECURE=RAM copy missing MISSING_SECURE=encrypted copy missing MISMATCH=hash mismatch")

	for _, entry := range trackedEntries {
		observed, err := observeListTrackedEntry(entry, key, kmsCfg)
		if err != nil {
			return err
		}
		fmt.Fprintln(out, formatListTrackedEntry(observed))
	}

	for _, tracked := range untracked {
		insecureHash, err := sha256File(tracked.InsecurePath)
		if err != nil {
			return fmt.Errorf("hash untracked insecure file %s: %w", tracked.InsecurePath, err)
		}
		fmt.Fprintf(out, "%s  insecure=%s  secure=MISSING  %s\n", tracked.Portable, hashOrMissing(insecureHash), statusUntrackedInsecure)
	}
	vlogf("list complete tracked=%d untracked=%d", len(trackedEntries), len(untracked))

	return nil
}

type listTrackedEntry struct {
	Portable string
	Paused   bool
	Tracked  trackedFile
}

type listTrackedObservation struct {
	Portable      string
	Paused        bool
	InsecureHash  string
	SecureHash    string
	InsecureFound bool
	SecureFound   bool
}

func collectListTrackedEntries(paths appPaths, cfg *config) ([]listTrackedEntry, map[string]struct{}, error) {
	trackedEntries := make([]listTrackedEntry, 0, len(cfg.ProtectedFiles))
	trackedRels := make(map[string]struct{}, len(cfg.ProtectedFiles))
	for _, entry := range cfg.ProtectedFiles {
		portable := entry.Path
		tracked, err := buildTrackedFileFromPortable(paths.Home, paths.SecureDir, paths.InsecureDir, portable)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve tracked path %s: %w", portable, err)
		}
		trackedEntries = append(trackedEntries, listTrackedEntry{Portable: portable, Paused: entry.Paused, Tracked: tracked})
		trackedRels[tracked.Rel] = struct{}{}
	}
	return trackedEntries, trackedRels, nil
}

func needsListKey(trackedEntries []listTrackedEntry) bool {
	for _, entry := range trackedEntries {
		if fileExists(entry.Tracked.SecurePath) {
			return true
		}
	}
	return false
}

func observeListTrackedEntry(entry listTrackedEntry, key []byte, kmsCfg kmsRuntimeConfig) (listTrackedObservation, error) {
	observed := listTrackedObservation{
		Portable:      entry.Portable,
		Paused:        entry.Paused,
		InsecureFound: fileExists(entry.Tracked.InsecurePath),
		SecureFound:   fileExists(entry.Tracked.SecurePath),
	}

	if observed.InsecureFound {
		hash, err := sha256File(entry.Tracked.InsecurePath)
		if err != nil {
			return listTrackedObservation{}, fmt.Errorf("hash insecure file %s: %w", entry.Tracked.InsecurePath, err)
		}
		observed.InsecureHash = hash
	}

	if observed.SecureFound && key != nil {
		ciphertext, err := os.ReadFile(entry.Tracked.SecurePath)
		if err != nil {
			return listTrackedObservation{}, fmt.Errorf("read secure file %s: %w", entry.Tracked.SecurePath, err)
		}
		plaintext, err := decryptBytesWithProfile(ciphertext, key, kmsCfg.Profile)
		if err != nil {
			return listTrackedObservation{}, fmt.Errorf("decrypt secure file %s: %w", entry.Tracked.SecurePath, err)
		}
		observed.SecureHash = fmt.Sprintf("%x", sha256.Sum256(plaintext))
	}
	return observed, nil
}

func planTrackedListStatus(observed listTrackedObservation) listStatus {
	switch {
	case !observed.InsecureFound:
		return statusMissingInsecure
	case !observed.SecureFound:
		return statusMissingSecure
	case observed.InsecureHash != observed.SecureHash:
		return statusMismatch
	default:
		return statusOK
	}
}

func formatListTrackedEntry(observed listTrackedObservation) string {
	pausedSuffix := ""
	if observed.Paused {
		pausedSuffix = "  PAUSED"
	}
	status := planTrackedListStatus(observed)
	return fmt.Sprintf(
		"%s  insecure=%s  secure=%s  %s%s",
		observed.Portable,
		hashOrMissing(observed.InsecureHash),
		hashOrMissing(observed.SecureHash),
		status,
		pausedSuffix,
	)
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
