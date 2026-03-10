package lokeys

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

func ensureEncryptedDir(path string) error {
	return os.MkdirAll(path, dirPerm)
}

func ensureParentDir(path string) error {
	return os.MkdirAll(filepath.Dir(path), dirPerm)
}

func ensureRegularFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("path is a symlink: %s", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("path is not a regular file: %s", path)
	}
	return nil
}

func copyFile(src, dst string, perm os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, perm)
}

func replaceWithSymlink(path string, target string) error {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			current, err := os.Readlink(path)
			if err != nil {
				return err
			}
			if current == target {
				return nil
			}
			return fmt.Errorf("symlink points elsewhere: %s", path)
		}
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Symlink(target, path)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func hashOrMissing(value string) string {
	if value == "" {
		return "MISSING"
	}
	return value
}

func containsString(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func createBackupTar(secureDir string, configPath string) (string, error) {
	if err := ensureEncryptedDir(secureDir); err != nil {
		return "", err
	}

	backupName := fmt.Sprintf("%d.tar", time.Now().Unix())
	backupPath := filepath.Join(secureDir, backupName)

	out, err := os.OpenFile(backupPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", err
	}
	defer out.Close()

	tw := tar.NewWriter(out)
	defer tw.Close()

	if err := filepath.WalkDir(secureDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == secureDir || path == backupPath {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}
		if !d.IsDir() && !info.Mode().IsRegular() {
			return nil
		}

		relPath, err := filepath.Rel(secureDir, path)
		if err != nil {
			return err
		}

		head, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		head.Name = filepath.ToSlash(relPath)
		if d.IsDir() {
			head.Name += "/"
		}
		if err := tw.WriteHeader(head); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		in, err := os.Open(path)
		if err != nil {
			return err
		}
		if _, err := io.Copy(tw, in); err != nil {
			in.Close()
			return err
		}
		if err := in.Close(); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return "", err
	}

	if err := addFileToTar(tw, configPath, filepath.ToSlash(configFileRel)); err != nil {
		return "", err
	}

	return backupPath, nil
}

func addFileToTar(tw *tar.Writer, absPath string, tarPath string) error {
	info, err := os.Stat(absPath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file: %s", absPath)
	}

	head, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	head.Name = tarPath
	if err := tw.WriteHeader(head); err != nil {
		return err
	}

	in, err := os.Open(absPath)
	if err != nil {
		return err
	}
	if _, err := io.Copy(tw, in); err != nil {
		in.Close()
		return err
	}
	if err := in.Close(); err != nil {
		return err
	}
	return nil
}
