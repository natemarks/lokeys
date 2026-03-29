package lokeys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This module validates session-key error handling on command entrypoints.
//
// The test intentionally sets malformed env key material and asserts the
// command fails with a parsing-focused, actionable error.

// TestRunListFailsFastWithWrongSessionKey verifies list fails before decrypting
// anything when the session env var is malformed.
func TestRunListFailsFastWithWrongSessionKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	fullPath := filepath.Join(home, "jjj", "jjj.txt")
	rel, err := relToHome(fullPath)
	if err != nil {
		t.Fatalf("RelToHome: %v", err)
	}

	securePath := filepath.Join(home, defaultEncryptedRel, rel)
	if err := os.MkdirAll(filepath.Dir(securePath), dirPerm); err != nil {
		t.Fatalf("mkdir secure dir: %v", err)
	}

	goodKey, _, err := deriveKeyFromPassphrase("this is a sufficiently long passphrase")
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}

	ciphertext, err := encryptBytes([]byte("secret payload"), goodKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := os.WriteFile(securePath, ciphertext, 0600); err != nil {
		t.Fatalf("write secure file: %v", err)
	}

	cfg := &config{ProtectedFiles: protectedFilesFromPaths([]string{"$HOME/jjj/jjj.txt"})}
	if err := os.MkdirAll(filepath.Join(home, ".config"), dirPerm); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	if err := writeConfig(cfg); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv(SessionKeyEnv, "this-is-definitely-the-wrong-key")
	err = RunList()
	if err == nil {
		t.Fatalf("expected error with wrong key")
	}
	if !strings.Contains(err.Error(), "must contain an encoded 32-byte key") {
		t.Fatalf("expected encoded session key error, got: %v", err)
	}
}
