package lokeys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This module validates key source and key validation behavior.
//
// Test strategy:
// - directly exercise env parsing and key decoding,
// - create encrypted fixtures on disk to verify validation errors are surfaced
//   in predictable, user-facing language.

// TestKeyFromSessionEnv_InvalidBase64_ErrorsWithEnvName ensures malformed env
// values produce actionable errors that name the expected variable.
func TestKeyFromSessionEnv_InvalidBase64_ErrorsWithEnvName(t *testing.T) {
	t.Setenv(SessionKeyEnv, "not-base64")
	_, _, err := keyFromSessionEnv()
	if err == nil {
		t.Fatalf("expected decode error")
	}
	if !strings.Contains(err.Error(), SessionKeyEnv) {
		t.Fatalf("expected env var name in error, got: %v", err)
	}
}

// TestKeyFromSessionEnv_InvalidLength_Errors ensures base64-decoded payloads
// with incorrect length are rejected.
func TestKeyFromSessionEnv_InvalidLength_Errors(t *testing.T) {
	t.Setenv(SessionKeyEnv, "YWJj")
	_, _, err := keyFromSessionEnv()
	if err == nil {
		t.Fatalf("expected length error")
	}
	if !strings.Contains(err.Error(), "32-byte") {
		t.Fatalf("expected length detail, got: %v", err)
	}
}

// TestValidateKeyForExistingProtectedFiles_WrongKey_Errors verifies key
// validation fails when at least one protected encrypted file cannot be
// decrypted with the provided key.
func TestValidateKeyForExistingProtectedFiles_WrongKey_Errors(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	securePath := filepath.Join(home, defaultEncryptedRel, "notes", "a.txt")
	if err := os.MkdirAll(filepath.Dir(securePath), dirPerm); err != nil {
		t.Fatalf("mkdir secure parent: %v", err)
	}

	goodKey, _, err := deriveKeyFromPassphrase("this is a sufficiently long good passphrase")
	if err != nil {
		t.Fatalf("derive good key: %v", err)
	}
	wrongKey, _, err := deriveKeyFromPassphrase("this is a sufficiently long wrong passphrase")
	if err != nil {
		t.Fatalf("derive wrong key: %v", err)
	}

	ciphertext, err := encryptBytes([]byte("secret"), goodKey)
	if err != nil {
		t.Fatalf("encryptBytes: %v", err)
	}
	if err := os.WriteFile(securePath, ciphertext, 0600); err != nil {
		t.Fatalf("write secure file: %v", err)
	}

	cfg := &config{ProtectedFiles: []string{"$HOME/notes/a.txt"}}
	err = validateKeyForExistingProtectedFiles(cfg, wrongKey)
	if err == nil {
		t.Fatalf("expected validation error")
	}
	if !strings.Contains(err.Error(), "invalid encryption key") {
		t.Fatalf("unexpected error: %v", err)
	}
}
