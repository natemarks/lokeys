package lokeys

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// RunRestore restores config and secure content from backup archive.
func RunRestore(archiveArg string) (string, int, error) {
	return defaultService().RunRestore(archiveArg)
}

// RunRestore restores config and secure content from backup archive.
func (s *Service) RunRestore(archiveArg string) (string, int, error) {
	paths, err := s.appPaths()
	if err != nil {
		return "", 0, err
	}

	archivePath, err := resolveRestoreArchive(paths, archiveArg)
	if err != nil {
		return "", 0, err
	}

	restoredCount, err := restoreFromArchive(archivePath, paths)
	if err != nil {
		return "", 0, err
	}

	if _, err := readConfig(paths.ConfigPath); err != nil {
		return "", 0, fmt.Errorf("restore did not produce valid config at %s: %w", paths.ConfigPath, err)
	}

	if err := s.deps.Mounter.EnsureMounted(paths.InsecureDir); err != nil {
		return "", 0, fmt.Errorf("ensure ramdisk mounted: %w", err)
	}

	return archivePath, restoredCount, nil
}

func resolveRestoreArchive(paths appPaths, archiveArg string) (string, error) {
	if strings.TrimSpace(archiveArg) == "" {
		return newestTarGz(paths.SecureDir)
	}

	candidate := archiveArg
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(paths.SecureDir, candidate)
	}
	if filepath.Ext(candidate) != ".gz" || !strings.HasSuffix(candidate, ".tar.gz") {
		return "", fmt.Errorf("restore archive must be a .tar.gz file: %s", candidate)
	}
	if _, err := os.Stat(candidate); err != nil {
		return "", fmt.Errorf("restore archive not found: %s", candidate)
	}
	return candidate, nil
}

func newestTarGz(secureDir string) (string, error) {
	entries, err := os.ReadDir(secureDir)
	if err != nil {
		return "", fmt.Errorf("read secure dir %s: %w", secureDir, err)
	}
	type candidate struct {
		path string
		mod  int64
	}
	items := make([]candidate, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tar.gz") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return "", err
		}
		items = append(items, candidate{path: filepath.Join(secureDir, entry.Name()), mod: info.ModTime().UnixNano()})
	}
	if len(items) == 0 {
		return "", fmt.Errorf("no backup archives found in %s", secureDir)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].mod == items[j].mod {
			return items[i].path > items[j].path
		}
		return items[i].mod > items[j].mod
	})
	return items[0].path, nil
}

func restoreFromArchive(archivePath string, paths appPaths) (int, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return 0, err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	restoredCount := 0
	restoredConfig := false

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}

		relSlash := filepath.ToSlash(filepath.Clean(hdr.Name))
		if relSlash == "." {
			continue
		}

		base := paths.SecureDir
		isConfig := relSlash == filepath.ToSlash(configFileRel)
		if isConfig {
			base = paths.Home
		}
		target, err := safeJoinUnder(base, filepath.FromSlash(relSlash))
		if err != nil {
			return 0, fmt.Errorf("unsafe archive entry %q: %w", hdr.Name, err)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, dirPerm); err != nil {
				return 0, err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := ensureParentDir(target); err != nil {
				return 0, err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				return 0, err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return 0, err
			}
			if err := out.Close(); err != nil {
				return 0, err
			}
			if isConfig {
				restoredConfig = true
			} else {
				restoredCount++
			}
		default:
			return 0, fmt.Errorf("unsupported archive entry type %d for %s", hdr.Typeflag, hdr.Name)
		}
	}

	if !restoredConfig {
		return 0, fmt.Errorf("archive %s did not contain %s", archivePath, configFileRel)
	}

	return restoredCount, nil
}

func safeJoinUnder(base string, rel string) (string, error) {
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("absolute entry path not allowed")
	}
	cleanRel := filepath.Clean(rel)
	if cleanRel == "." || cleanRel == ".." || strings.HasPrefix(cleanRel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("path traversal not allowed")
	}
	target := filepath.Join(base, cleanRel)
	if _, err := relToBase(base, target); err != nil {
		return "", fmt.Errorf("target escapes base")
	}
	return target, nil
}
