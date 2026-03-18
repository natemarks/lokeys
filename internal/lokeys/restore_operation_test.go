package lokeys

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// This module validates restore orchestration and archive extraction safety for
// migration scenarios where only ~/.lokeys/secure is copied to a new machine.

type restoreMounter struct{ called bool }

func (m *restoreMounter) EnsureMounted(string) error {
	m.called = true
	return nil
}

// TestRunRestore_DefaultsToLatestArchive verifies restore picks the latest
// archive in secure storage when no archive argument is provided.
//
// How it works:
// 1. Create two timestamped archives in secure storage.
// 2. Remove config and secure data to simulate a fresh machine state.
// 3. Run restore with empty arg and assert newest archive path is selected.
func TestRunRestore_DefaultsToLatestArchive(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	secureDir := filepath.Join(home, defaultEncryptedRel)
	configPath := filepath.Join(home, configFileRel)
	if err := os.MkdirAll(filepath.Join(secureDir, "notes"), dirPerm); err != nil {
		t.Fatalf("mkdir secure parent: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(configPath), dirPerm); err != nil {
		t.Fatalf("mkdir config parent: %v", err)
	}
	if err := os.WriteFile(filepath.Join(secureDir, "notes", "a.enc"), []byte("cipher-a"), 0600); err != nil {
		t.Fatalf("write secure file: %v", err)
	}
	if err := os.WriteFile(configPath, []byte(`{"protectedFiles":["$HOME/notes/a.txt"]}`), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	oldArchive, err := createBackupTarGzWithNow(secureDir, configPath, func() time.Time { return time.Unix(100, 0) })
	if err != nil {
		t.Fatalf("create old archive: %v", err)
	}
	newArchive, err := createBackupTarGzWithNow(secureDir, configPath, func() time.Time { return time.Unix(200, 0) })
	if err != nil {
		t.Fatalf("create new archive: %v", err)
	}

	if err := os.RemoveAll(filepath.Join(secureDir, "notes")); err != nil {
		t.Fatalf("remove secure notes: %v", err)
	}
	if err := os.Remove(configPath); err != nil {
		t.Fatalf("remove config: %v", err)
	}

	mounter := &restoreMounter{}
	svc := NewService(Deps{Mounter: mounter, Keys: testKeySource{}, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	path, _, err := svc.RunRestore("")
	if err != nil {
		t.Fatalf("RunRestore: %v", err)
	}
	if path != newArchive {
		t.Fatalf("expected newest archive %s, got %s (old=%s)", newArchive, path, oldArchive)
	}
	if !mounter.called {
		t.Fatalf("expected mounter to be called")
	}
}

// TestRunRestore_UsesSpecifiedArchive verifies restore honors an explicit
// archive basename located under secure storage.
//
// How it works:
// 1. Create one archive in secure storage.
// 2. Remove config to force restoration from archive.
// 3. Run restore with archive basename and assert selected archive matches.
func TestRunRestore_UsesSpecifiedArchive(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	secureDir := filepath.Join(home, defaultEncryptedRel)
	configPath := filepath.Join(home, configFileRel)
	if err := os.MkdirAll(filepath.Join(secureDir, "notes"), dirPerm); err != nil {
		t.Fatalf("mkdir secure parent: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(configPath), dirPerm); err != nil {
		t.Fatalf("mkdir config parent: %v", err)
	}
	if err := os.WriteFile(filepath.Join(secureDir, "notes", "b.enc"), []byte("cipher-b"), 0600); err != nil {
		t.Fatalf("write secure file: %v", err)
	}
	if err := os.WriteFile(configPath, []byte(`{"protectedFiles":["$HOME/notes/b.txt"]}`), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	archivePath, err := createBackupTarGzWithNow(secureDir, configPath, func() time.Time { return time.Unix(300, 0) })
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	if err := os.Remove(configPath); err != nil {
		t.Fatalf("remove config: %v", err)
	}

	svc := NewService(Deps{Mounter: &restoreMounter{}, Keys: testKeySource{}, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	selected, restoredCount, err := svc.RunRestore(filepath.Base(archivePath))
	if err != nil {
		t.Fatalf("RunRestore: %v", err)
	}
	if selected != archivePath {
		t.Fatalf("expected archive %s, got %s", archivePath, selected)
	}
	if restoredCount == 0 {
		t.Fatalf("expected restored encrypted file count > 0")
	}
}

// TestRestoreFromArchive_RejectsPathTraversal verifies tar extraction rejects
// traversal entries and fails safely.
//
// How it works:
// 1. Create a tar.gz containing ../ traversal entry.
// 2. Call restoreFromArchive directly.
// 3. Assert extraction fails with an unsafe-entry error.
func TestRestoreFromArchive_RejectsPathTraversal(t *testing.T) {
	home := t.TempDir()
	archivePath := filepath.Join(home, "bad.tar.gz")

	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)
	content := []byte("oops")
	hdr := &tar.Header{Name: "../escape.txt", Mode: 0600, Size: int64(len(content)), Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("write body: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	if err := os.WriteFile(archivePath, buf.Bytes(), 0600); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	paths := appPaths{Home: home, ConfigPath: filepath.Join(home, configFileRel), SecureDir: filepath.Join(home, defaultEncryptedRel), InsecureDir: filepath.Join(home, defaultDecryptedRel)}
	_, err := restoreFromArchive(archivePath, paths)
	if err == nil {
		t.Fatalf("expected traversal error")
	}
}
