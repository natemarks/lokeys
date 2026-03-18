package lokeys

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This module validates list-specific behavior beyond core tracked-file status
// reporting, including discovery of externally created insecure files.

// TestRunList_ShowsExternallyCreatedInsecureFileAsUntracked verifies list
// surfaces untracked files that were created directly under the RAM-disk tree.
//
// How it works:
// 1. Create an empty config under a temp HOME.
// 2. Write a regular file directly in ~/.lokeys/insecure outside tracked config.
// 3. Run list with captured stdout and assert UNTRACKED_INSECURE output.
func TestRunList_ShowsExternallyCreatedInsecureFileAsUntracked(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if _, _, err := ensureConfig(); err != nil {
		t.Fatalf("ensure config: %v", err)
	}
	insecurePath := filepath.Join(home, defaultDecryptedRel, "external", "new.txt")
	if err := os.MkdirAll(filepath.Dir(insecurePath), dirPerm); err != nil {
		t.Fatalf("mkdir insecure parent: %v", err)
	}
	if err := os.WriteFile(insecurePath, []byte("external\n"), 0600); err != nil {
		t.Fatalf("write insecure file: %v", err)
	}

	stdout := &bytes.Buffer{}
	svc := NewService(Deps{Stdout: stdout, Stderr: &bytes.Buffer{}, Mounter: testMounter{}, Keys: testKeySource{}})
	if err := svc.RunList(); err != nil {
		t.Fatalf("RunList: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "$HOME/external/new.txt") {
		t.Fatalf("expected derived portable path in output, got: %q", out)
	}
	if !strings.Contains(out, "UNTRACKED_INSECURE") {
		t.Fatalf("expected untracked insecure status in output, got: %q", out)
	}
}
