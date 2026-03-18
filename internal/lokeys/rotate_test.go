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
)

// This module validates key rotation semantics including pre-rotation backup,
// key source behavior, and safety checks.
//
// Test strategy:
// - model tracked files under temp HOME,
// - stub mount and prompt boundaries only,
// - keep real crypto/backup code paths to verify wire compatibility.

// TestRunRotateUsesRamdiskContentAndCreatesTarGzBackup verifies rotation uses
// latest RAM-disk plaintext as source of truth, writes a backup archive, and
// re-encrypts with the new key.
func TestRunRotateUsesRamdiskContentAndCreatesTarGzBackup(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	oldKey, oldEncoded, err := deriveKeyFromPassphrase("this is a sufficiently long old passphrase")
	if err != nil {
		t.Fatalf("derive old key: %v", err)
	}
	newKey, _, err := deriveKeyFromPassphrase("this is a sufficiently long new passphrase")
	if err != nil {
		t.Fatalf("derive new key: %v", err)
	}
	t.Setenv(SessionKeyEnv, oldEncoded)

	svc := newTestServiceWithOpts(testServiceOpts{newKeyPrompt: newKey})
	if _, _, err := ensureConfig(); err != nil {
		t.Fatalf("ensure config: %v", err)
	}

	trackedPortable := "$HOME/notes/rotate.txt"
	if err := writeConfig(&config{ProtectedFiles: []string{trackedPortable}}); err != nil {
		t.Fatalf("write config: %v", err)
	}

	insecurePath := filepath.Join(home, defaultDecryptedRel, "notes", "rotate.txt")
	securePath := filepath.Join(home, defaultEncryptedRel, "notes", "rotate.txt")
	if err := os.MkdirAll(filepath.Dir(insecurePath), dirPerm); err != nil {
		t.Fatalf("mkdir insecure parent: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(securePath), dirPerm); err != nil {
		t.Fatalf("mkdir secure parent: %v", err)
	}

	ramContent := []byte("latest-ram-value\n")
	if err := os.WriteFile(insecurePath, ramContent, 0600); err != nil {
		t.Fatalf("write insecure file: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(home, "notes"), dirPerm); err != nil {
		t.Fatalf("mkdir home parent: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, "notes", "rotate.txt"), []byte("placeholder\n"), 0600); err != nil {
		t.Fatalf("write home file: %v", err)
	}
	staleCiphertext, err := encryptBytes([]byte("stale-secure-value\n"), oldKey)
	if err != nil {
		t.Fatalf("encrypt stale value: %v", err)
	}
	if err := os.WriteFile(securePath, staleCiphertext, 0600); err != nil {
		t.Fatalf("write secure file: %v", err)
	}

	backupPath, rotated, err := svc.RunRotate()
	if err != nil {
		t.Fatalf("RunRotate failed: %v", err)
	}
	if rotated != 1 {
		t.Fatalf("rotated count mismatch: got %d want 1", rotated)
	}
	if !strings.HasSuffix(backupPath, ".tar.gz") {
		t.Fatalf("backup extension mismatch: %s", backupPath)
	}

	backupEntry, err := readTarGzEntry(backupPath, "notes/rotate.txt")
	if err != nil {
		t.Fatalf("read backup entry: %v", err)
	}
	backupPlaintext, err := decryptBytes(backupEntry, oldKey)
	if err != nil {
		t.Fatalf("decrypt backup entry with old key: %v", err)
	}
	if string(backupPlaintext) != string(ramContent) {
		t.Fatalf("backup did not preserve RAM content: got %q want %q", string(backupPlaintext), string(ramContent))
	}

	rotatedCiphertext, err := os.ReadFile(securePath)
	if err != nil {
		t.Fatalf("read rotated secure file: %v", err)
	}
	rotatedPlaintext, err := decryptBytes(rotatedCiphertext, newKey)
	if err != nil {
		t.Fatalf("decrypt rotated ciphertext with new key: %v", err)
	}
	if string(rotatedPlaintext) != string(ramContent) {
		t.Fatalf("rotated plaintext mismatch: got %q want %q", string(rotatedPlaintext), string(ramContent))
	}
	if _, err := decryptBytes(rotatedCiphertext, oldKey); err == nil {
		t.Fatalf("expected old key to fail on rotated ciphertext")
	}
}

// TestRunRotatePromptsOldKeyWhenEnvMissing verifies the old-key prompt path is
// used when session env is not available.
func TestRunRotatePromptsOldKeyWhenEnvMissing(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(SessionKeyEnv, "")

	oldKey, _, err := deriveKeyFromPassphrase("this is a sufficiently long old passphrase")
	if err != nil {
		t.Fatalf("derive old key: %v", err)
	}
	newKey, _, err := deriveKeyFromPassphrase("this is a sufficiently long new passphrase")
	if err != nil {
		t.Fatalf("derive new key: %v", err)
	}

	svc := newTestServiceWithOpts(testServiceOpts{newKeyPrompt: newKey, oldKeyPrompt: oldKey})
	if _, _, err := ensureConfig(); err != nil {
		t.Fatalf("ensure config: %v", err)
	}

	trackedPortable := "$HOME/notes/prompt.txt"
	if err := writeConfig(&config{ProtectedFiles: []string{trackedPortable}}); err != nil {
		t.Fatalf("write config: %v", err)
	}

	insecurePath := filepath.Join(home, defaultDecryptedRel, "notes", "prompt.txt")
	securePath := filepath.Join(home, defaultEncryptedRel, "notes", "prompt.txt")
	if err := os.MkdirAll(filepath.Dir(insecurePath), dirPerm); err != nil {
		t.Fatalf("mkdir insecure parent: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(securePath), dirPerm); err != nil {
		t.Fatalf("mkdir secure parent: %v", err)
	}
	if err := os.WriteFile(insecurePath, []byte("prompt-ram\n"), 0600); err != nil {
		t.Fatalf("write insecure file: %v", err)
	}
	ciphertext, err := encryptBytes([]byte("prompt-old\n"), oldKey)
	if err != nil {
		t.Fatalf("encrypt old value: %v", err)
	}
	if err := os.WriteFile(securePath, ciphertext, 0600); err != nil {
		t.Fatalf("write secure file: %v", err)
	}

	_, rotated, err := svc.RunRotate()
	if err != nil {
		t.Fatalf("RunRotate failed: %v", err)
	}
	if rotated != 1 {
		t.Fatalf("rotated count mismatch: got %d want 1", rotated)
	}
}

// TestRunRotateRejectsSameOldAndNewKey verifies rotation refuses no-op key
// changes to prevent misleading success output without cryptographic change.
func TestRunRotateRejectsSameOldAndNewKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	oldKey, oldEncoded, err := deriveKeyFromPassphrase("this is a sufficiently long old passphrase")
	if err != nil {
		t.Fatalf("derive old key: %v", err)
	}
	t.Setenv(SessionKeyEnv, oldEncoded)

	svc := newTestServiceWithOpts(testServiceOpts{newKeyPrompt: oldKey})
	if _, _, err := ensureConfig(); err != nil {
		t.Fatalf("ensure config: %v", err)
	}

	trackedPortable := "$HOME/notes/same-key.txt"
	if err := writeConfig(&config{ProtectedFiles: []string{trackedPortable}}); err != nil {
		t.Fatalf("write config: %v", err)
	}

	insecurePath := filepath.Join(home, defaultDecryptedRel, "notes", "same-key.txt")
	if err := os.MkdirAll(filepath.Dir(insecurePath), dirPerm); err != nil {
		t.Fatalf("mkdir insecure parent: %v", err)
	}
	if err := os.WriteFile(insecurePath, []byte("same-key\n"), 0600); err != nil {
		t.Fatalf("write insecure file: %v", err)
	}

	_, _, err = svc.RunRotate()
	if err == nil {
		t.Fatalf("expected same-key error")
	}
	if !strings.Contains(err.Error(), "must differ") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestRunRotate_EnrollsAndRotatesDiscoveredInsecureFiles verifies rotate also
// promotes newly discovered insecure files before key rotation begins.
//
// How it works:
// 1. Configure one tracked file and one externally created insecure file.
// 2. Run rotate with old/new keys.
// 3. Assert discovered file is enrolled and decrypts with new key only.
func TestRunRotate_EnrollsAndRotatesDiscoveredInsecureFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	oldKey, oldEncoded, err := deriveKeyFromPassphrase("this is a sufficiently long old passphrase")
	if err != nil {
		t.Fatalf("derive old key: %v", err)
	}
	newKey, _, err := deriveKeyFromPassphrase("this is a sufficiently long new passphrase")
	if err != nil {
		t.Fatalf("derive new key: %v", err)
	}
	t.Setenv(SessionKeyEnv, oldEncoded)

	svc := newTestServiceWithOpts(testServiceOpts{newKeyPrompt: newKey})
	if _, _, err := ensureConfig(); err != nil {
		t.Fatalf("ensure config: %v", err)
	}
	if err := writeConfig(&config{ProtectedFiles: []string{"$HOME/tracked/base.txt"}}); err != nil {
		t.Fatalf("write config: %v", err)
	}

	trackedInsecure := filepath.Join(home, defaultDecryptedRel, "tracked", "base.txt")
	if err := os.MkdirAll(filepath.Dir(trackedInsecure), dirPerm); err != nil {
		t.Fatalf("mkdir tracked insecure parent: %v", err)
	}
	if err := os.WriteFile(trackedInsecure, []byte("tracked-data\n"), 0600); err != nil {
		t.Fatalf("write tracked insecure: %v", err)
	}

	discoveredInsecure := filepath.Join(home, defaultDecryptedRel, "external-rotate", "new.txt")
	if err := os.MkdirAll(filepath.Dir(discoveredInsecure), dirPerm); err != nil {
		t.Fatalf("mkdir discovered insecure parent: %v", err)
	}
	if err := os.WriteFile(discoveredInsecure, []byte("discovered-data\n"), 0600); err != nil {
		t.Fatalf("write discovered insecure: %v", err)
	}

	_, rotated, err := svc.RunRotate()
	if err != nil {
		t.Fatalf("RunRotate: %v", err)
	}
	if rotated != 2 {
		t.Fatalf("expected 2 rotated files (tracked + discovered), got %d", rotated)
	}

	cfg, err := readConfig(filepath.Join(home, configFileRel))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !containsString(cfg.ProtectedFiles, "$HOME/external-rotate/new.txt") {
		t.Fatalf("expected discovered file enrollment, got %#v", cfg.ProtectedFiles)
	}

	secureDiscovered := filepath.Join(home, defaultEncryptedRel, "external-rotate", "new.txt")
	ciphertext, err := os.ReadFile(secureDiscovered)
	if err != nil {
		t.Fatalf("read discovered secure file: %v", err)
	}
	plainNew, err := decryptBytes(ciphertext, newKey)
	if err != nil {
		t.Fatalf("decrypt discovered with new key: %v", err)
	}
	if string(plainNew) != "discovered-data\n" {
		t.Fatalf("unexpected discovered plaintext: %q", string(plainNew))
	}
	if _, err := decryptBytes(ciphertext, oldKey); err == nil {
		t.Fatalf("expected old key to fail for discovered rotated file")
	}
}

// readTarGzEntry fetches one named archive entry from backup output for direct
// decryption/assertion in rotation tests.
func readTarGzEntry(archivePath string, entryName string) ([]byte, error) {
	f, err := os.Open(archivePath)
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
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Name != entryName {
			continue
		}
		return io.ReadAll(tr)
	}
	return nil, os.ErrNotExist
}
