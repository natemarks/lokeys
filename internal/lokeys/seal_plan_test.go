package lokeys

import (
	"os"
	"path/filepath"
	"testing"
)

// This module validates seal-plan action generation for tracked and discovered
// files before side effects are applied.

// TestPlanSeal_WithDiscoveredFiles_AppendsConfigWrite verifies discovered RAM
// files result in enrollment actions and a trailing config write.
//
// How it works:
// 1. Build one tracked and one discovered trackedFile fixture.
// 2. Generate a seal plan.
// 3. Assert the last action persists updated config enrollment.
func TestPlanSeal_WithDiscoveredFiles_AppendsConfigWrite(t *testing.T) {
	paths := appPaths{SecureDir: "/secure"}
	cfg := &config{ProtectedFiles: protectedFilesFromPaths([]string{"$HOME/a.txt"})}
	tracked := []trackedFile{{Portable: "$HOME/a.txt", InsecurePath: "/ram/a.txt", SecurePath: "/secure/a.txt"}}
	discovered := []trackedFile{{Portable: "$HOME/b.txt", HomePath: "/home/u/b.txt", InsecurePath: "/ram/b.txt", SecurePath: "/secure/b.txt"}}

	p, _ := planSeal(paths, cfg, tracked, discovered, []byte("k"), nil)
	if len(p.Actions) == 0 {
		t.Fatalf("expected plan actions")
	}
	if got := p.Actions[len(p.Actions)-1].Kind; got != actionWriteConfig {
		t.Fatalf("expected last action write config, got %s", got)
	}
}

// TestPlanSeal_NoDiscoveredFiles_SkipsConfigWrite verifies seal planning keeps
// config untouched when no newly discovered files are enrolled.
//
// How it works:
// 1. Build a seal plan with only pre-existing tracked files.
// 2. Scan actions for actionWriteConfig.
// 3. Assert it is absent so config is not rewritten unnecessarily.
func TestPlanSeal_NoDiscoveredFiles_SkipsConfigWrite(t *testing.T) {
	p, _ := planSeal(appPaths{SecureDir: "/secure"}, &config{ProtectedFiles: protectedFilesFromPaths([]string{"$HOME/a.txt"})}, []trackedFile{{InsecurePath: "/ram/a.txt", SecurePath: "/secure/a.txt"}}, nil, []byte("k"), nil)
	for _, a := range p.Actions {
		if a.Kind == actionWriteConfig {
			t.Fatalf("did not expect config write when no discovered files")
		}
	}
}

func TestPlanSeal_SkipsTrackedWhenInsecureMissing(t *testing.T) {
	root := t.TempDir()
	presentInsecure := filepath.Join(root, "ram", "present.txt")
	if err := os.MkdirAll(filepath.Dir(presentInsecure), dirPerm); err != nil {
		t.Fatalf("mkdir present insecure parent: %v", err)
	}
	if err := os.WriteFile(presentInsecure, []byte("present\n"), 0600); err != nil {
		t.Fatalf("write present insecure: %v", err)
	}

	tracked := []trackedFile{
		{Portable: "$HOME/present.txt", InsecurePath: presentInsecure, SecurePath: filepath.Join(root, "secure", "present.txt")},
		{Portable: "$HOME/missing.txt", InsecurePath: filepath.Join(root, "ram", "missing.txt"), SecurePath: filepath.Join(root, "secure", "missing.txt")},
	}

	p, _ := planSeal(appPaths{SecureDir: filepath.Join(root, "secure")}, &config{ProtectedFiles: protectedFilesFromPaths([]string{"$HOME/present.txt", "$HOME/missing.txt"})}, tracked, nil, []byte("k"), nil)

	encryptCount := 0
	for _, a := range p.Actions {
		if a.Kind != actionEncryptFile {
			continue
		}
		encryptCount++
		if a.Source != presentInsecure {
			t.Fatalf("expected only present insecure source to be encrypted, got %s", a.Source)
		}
	}
	if encryptCount != 1 {
		t.Fatalf("expected one encrypt action for present tracked file, got %d", encryptCount)
	}
}
