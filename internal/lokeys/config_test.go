package lokeys

import (
	"os"
	"path/filepath"
	"testing"
)

// This module validates config persistence behavior.
//
// Test strategy:
// - write an initial config file,
// - replace it using writeConfigTo (temp-file + rename path),
// - read config back and verify the new payload is present.

// TestWriteConfigTo_ReplacesConfigContents verifies writeConfigTo performs an
// atomic replace pattern that leaves the target file readable with updated data.
func TestWriteConfigTo_ReplacesConfigContents(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "lokeys.json")

	if err := os.WriteFile(path, []byte(`{"protectedFiles":["$HOME/old.txt"]}`), 0600); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	want := &config{ProtectedFiles: []string{"$HOME/new.txt", "$HOME/next.txt"}}
	if err := writeConfigTo(path, want); err != nil {
		t.Fatalf("writeConfigTo: %v", err)
	}

	got, err := readConfig(path)
	if err != nil {
		t.Fatalf("readConfig: %v", err)
	}
	if len(got.ProtectedFiles) != 2 || got.ProtectedFiles[0] != "$HOME/new.txt" || got.ProtectedFiles[1] != "$HOME/next.txt" {
		t.Fatalf("unexpected protected files: %#v", got.ProtectedFiles)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if info.Mode().Perm() != configFilePerm {
		t.Fatalf("unexpected mode: got %o want %o", info.Mode().Perm(), configFilePerm)
	}
}
