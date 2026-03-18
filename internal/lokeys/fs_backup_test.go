package lokeys

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This module validates backup archive generation and archive contents.
//
// Test strategy:
// - create a realistic secure tree + config file fixture,
// - generate a tar.gz backup,
// - inspect resulting archive entries to assert required files are included.

// TestCreateBackupTarGzCreatesCompressedArchive verifies backup output format
// and required entries (encrypted data and config).
func TestCreateBackupTarGzCreatesCompressedArchive(t *testing.T) {
	home := t.TempDir()
	secureDir := filepath.Join(home, "secure")
	configPath := filepath.Join(home, ".config", "lokeys")

	if err := os.MkdirAll(filepath.Join(secureDir, "nested"), dirPerm); err != nil {
		t.Fatalf("mkdir secure: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(configPath), dirPerm); err != nil {
		t.Fatalf("mkdir config parent: %v", err)
	}
	if err := os.WriteFile(filepath.Join(secureDir, "nested", "file.enc"), []byte("ciphertext"), 0600); err != nil {
		t.Fatalf("write secure file: %v", err)
	}
	if err := os.WriteFile(configPath, []byte(`{"protectedFiles":[]}`), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	backupPath, err := createBackupTarGzWithNow(secureDir, configPath, time.Now)
	if err != nil {
		t.Fatalf("createBackupTarGzWithNow: %v", err)
	}
	if !strings.HasSuffix(backupPath, ".tar.gz") {
		t.Fatalf("expected .tar.gz backup, got %s", backupPath)
	}

	names, err := listTarGzEntries(backupPath)
	if err != nil {
		t.Fatalf("list archive entries: %v", err)
	}
	if !containsString(names, "nested/file.enc") {
		t.Fatalf("missing secure entry: %#v", names)
	}
	if !containsString(names, filepath.ToSlash(configFileRel)) {
		t.Fatalf("missing config entry: %#v", names)
	}
}

// TestCreateBackupTarGzWithNow_UsesDeterministicTimestampName verifies the
// time hook yields deterministic backup filenames for stable tests.
func TestCreateBackupTarGzWithNow_UsesDeterministicTimestampName(t *testing.T) {
	home := t.TempDir()
	secureDir := filepath.Join(home, "secure")
	configPath := filepath.Join(home, ".config", "lokeys")
	if err := os.MkdirAll(filepath.Dir(configPath), dirPerm); err != nil {
		t.Fatalf("mkdir config parent: %v", err)
	}
	if err := os.WriteFile(configPath, []byte(`{"protectedFiles":[]}`), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	fixedNow := func() time.Time { return time.Unix(1700000000, 0) }
	backupPath, err := createBackupTarGzWithNow(secureDir, configPath, fixedNow)
	if err != nil {
		t.Fatalf("createBackupTarGzWithNow: %v", err)
	}
	if filepath.Base(backupPath) != "1700000000.tar.gz" {
		t.Fatalf("unexpected backup name: %s", filepath.Base(backupPath))
	}
}

// listTarGzEntries reads every entry name from a .tar.gz file so tests can
// assert inclusion semantics without depending on shell utilities.
func listTarGzEntries(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	names := []string{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		names = append(names, hdr.Name)
	}
	return names, nil
}
