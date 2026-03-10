package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunListFailsFastWithWrongSessionKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	fullPath := filepath.Join(home, "jjj", "jjj.txt")
	rel, err := relToHome(fullPath)
	if err != nil {
		t.Fatalf("relToHome: %v", err)
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

	cfg := &config{ProtectedFiles: []string{"$HOME/jjj/jjj.txt"}}
	if err := os.MkdirAll(filepath.Join(home, ".config"), dirPerm); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	if err := writeConfig(cfg); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv(sessionKeyEnv, "this-is-definitely-the-wrong-key")
	err = runList([]string{}, true)
	if err == nil {
		t.Fatalf("expected error with wrong key")
	}
	if !strings.Contains(err.Error(), "invalid encryption key") {
		t.Fatalf("expected invalid key error, got: %v", err)
	}
	if errors.Is(err, errUsage) {
		t.Fatalf("expected runtime failure, got usage error: %v", err)
	}
}
