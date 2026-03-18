package lokeys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This module exercises end-to-end command orchestration for add/seal flows
// using a temp HOME and a stubbed RAM-disk mount function.
//
// Test strategy:
// - keep crypto real to validate secure artifacts actually decrypt,
// - stub only mount interaction to avoid sudo/terminal coupling,
// - assert both filesystem side effects and config mutations.

// TestRunAddProtectsRamdiskCreatedFile verifies that adding a file created
// directly in the RAM-disk tree creates the derived home symlink, encrypted
// copy, and config enrollment entry.
func TestRunAddProtectsRamdiskCreatedFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	_, encoded := mustEncodedSessionKey(t)
	t.Setenv(SessionKeyEnv, encoded)

	svc := newTestService()

	insecurePath := filepath.Join(home, defaultDecryptedRel, "notes", "new.txt")
	if err := os.MkdirAll(filepath.Dir(insecurePath), dirPerm); err != nil {
		t.Fatalf("mkdir insecure parent: %v", err)
	}
	if err := os.WriteFile(insecurePath, []byte("secret\n"), 0600); err != nil {
		t.Fatalf("write insecure file: %v", err)
	}

	if err := svc.RunAdd(insecurePath); err != nil {
		t.Fatalf("RunAdd failed: %v", err)
	}

	homePath := filepath.Join(home, "notes", "new.txt")
	info, err := os.Lstat(homePath)
	if err != nil {
		t.Fatalf("stat home path: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected symlink at %s", homePath)
	}
	target, err := os.Readlink(homePath)
	if err != nil {
		t.Fatalf("read symlink: %v", err)
	}
	if target != insecurePath {
		t.Fatalf("symlink target mismatch: got %s want %s", target, insecurePath)
	}

	securePath := filepath.Join(home, defaultEncryptedRel, "notes", "new.txt")
	if !fileExists(securePath) {
		t.Fatalf("expected secure file at %s", securePath)
	}

	cfg, err := readConfig(filepath.Join(home, configFileRel))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !containsString(cfg.ProtectedFiles, "$HOME/notes/new.txt") {
		t.Fatalf("missing protected file entry: %#v", cfg.ProtectedFiles)
	}
}

// TestRunAddFailsWhenDerivedHomePathExists verifies conflict protection for
// RAM-origin files: if the derived canonical home path already exists, add must
// fail before any enrollment mutation.
func TestRunAddFailsWhenDerivedHomePathExists(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	_, encoded := mustEncodedSessionKey(t)
	t.Setenv(SessionKeyEnv, encoded)

	svc := newTestService()

	insecurePath := filepath.Join(home, defaultDecryptedRel, "notes", "conflict.txt")
	if err := os.MkdirAll(filepath.Dir(insecurePath), dirPerm); err != nil {
		t.Fatalf("mkdir insecure parent: %v", err)
	}
	if err := os.WriteFile(insecurePath, []byte("secret\n"), 0600); err != nil {
		t.Fatalf("write insecure file: %v", err)
	}

	homePath := filepath.Join(home, "notes", "conflict.txt")
	if err := os.MkdirAll(filepath.Dir(homePath), dirPerm); err != nil {
		t.Fatalf("mkdir home parent: %v", err)
	}
	if err := os.WriteFile(homePath, []byte("existing\n"), 0600); err != nil {
		t.Fatalf("write home file: %v", err)
	}

	err := svc.RunAdd(insecurePath)
	if err == nil {
		t.Fatalf("expected conflict error")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected exists error, got: %v", err)
	}
}

// TestRunSealDiscoversAndProtectsRamdiskFiles verifies seal auto-discovers
// untracked regular files in the RAM-disk tree and promotes them into managed
// protection state (encrypted file + symlink + config entry).
func TestRunSealDiscoversAndProtectsRamdiskFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	_, encoded := mustEncodedSessionKey(t)
	t.Setenv(SessionKeyEnv, encoded)

	svc := newTestService()

	if _, _, err := ensureConfig(); err != nil {
		t.Fatalf("ensure config: %v", err)
	}

	insecurePath := filepath.Join(home, defaultDecryptedRel, "notes", "seal-new.txt")
	if err := os.MkdirAll(filepath.Dir(insecurePath), dirPerm); err != nil {
		t.Fatalf("mkdir insecure parent: %v", err)
	}
	if err := os.WriteFile(insecurePath, []byte("secret\n"), 0600); err != nil {
		t.Fatalf("write insecure file: %v", err)
	}

	if err := svc.RunSeal(); err != nil {
		t.Fatalf("RunSeal failed: %v", err)
	}

	homePath := filepath.Join(home, "notes", "seal-new.txt")
	info, err := os.Lstat(homePath)
	if err != nil {
		t.Fatalf("stat home path: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected symlink at %s", homePath)
	}

	securePath := filepath.Join(home, defaultEncryptedRel, "notes", "seal-new.txt")
	if !fileExists(securePath) {
		t.Fatalf("expected secure file at %s", securePath)
	}

	cfg, err := readConfig(filepath.Join(home, configFileRel))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !containsString(cfg.ProtectedFiles, "$HOME/notes/seal-new.txt") {
		t.Fatalf("missing protected file entry: %#v", cfg.ProtectedFiles)
	}
}

// TestRunSealFailsFastOnFirstConflict verifies fail-fast semantics during
// discovery: if any RAM-disk file maps to an already-existing home path, seal
// aborts and does not partially protect unrelated files.
func TestRunSealFailsFastOnFirstConflict(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	_, encoded := mustEncodedSessionKey(t)
	t.Setenv(SessionKeyEnv, encoded)

	svc := newTestService()

	if _, _, err := ensureConfig(); err != nil {
		t.Fatalf("ensure config: %v", err)
	}

	conflictRAMPath := filepath.Join(home, defaultDecryptedRel, "a", "conflict.txt")
	safeRAMPath := filepath.Join(home, defaultDecryptedRel, "b", "safe.txt")
	if err := os.MkdirAll(filepath.Dir(conflictRAMPath), dirPerm); err != nil {
		t.Fatalf("mkdir conflict parent: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(safeRAMPath), dirPerm); err != nil {
		t.Fatalf("mkdir safe parent: %v", err)
	}
	if err := os.WriteFile(conflictRAMPath, []byte("conflict\n"), 0600); err != nil {
		t.Fatalf("write conflict file: %v", err)
	}
	if err := os.WriteFile(safeRAMPath, []byte("safe\n"), 0600); err != nil {
		t.Fatalf("write safe file: %v", err)
	}

	homeConflictPath := filepath.Join(home, "a", "conflict.txt")
	if err := os.MkdirAll(filepath.Dir(homeConflictPath), dirPerm); err != nil {
		t.Fatalf("mkdir home conflict parent: %v", err)
	}
	if err := os.WriteFile(homeConflictPath, []byte("existing\n"), 0600); err != nil {
		t.Fatalf("write home conflict file: %v", err)
	}

	err := svc.RunSeal()
	if err == nil {
		t.Fatalf("expected conflict error")
	}
	if !strings.Contains(err.Error(), "refusing to seal RAM-disk file") {
		t.Fatalf("unexpected error: %v", err)
	}

	safeHomePath := filepath.Join(home, "b", "safe.txt")
	if fileExists(safeHomePath) {
		t.Fatalf("expected no symlink at %s on conflict", safeHomePath)
	}

	safeSecurePath := filepath.Join(home, defaultEncryptedRel, "b", "safe.txt")
	if fileExists(safeSecurePath) {
		t.Fatalf("expected no secure file at %s on conflict", safeSecurePath)
	}

	cfg, err := readConfig(filepath.Join(home, configFileRel))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if len(cfg.ProtectedFiles) != 0 {
		t.Fatalf("expected unchanged config, got %#v", cfg.ProtectedFiles)
	}
}
