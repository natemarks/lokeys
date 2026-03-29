package lokeys

import (
	"path/filepath"
	"testing"
)

// This module validates add-plan generation without executing filesystem
// mutations, so test failures clearly indicate planning regressions.

// TestPlanAdd_NewHomeFile_ContainsExpectedActions verifies the add planner
// creates the expected action sequence for a non-RAM source file.
//
// How it works:
// 1. Build a synthetic tracked file under temp HOME paths.
// 2. Plan an add operation for a normal home-origin source.
// 3. Assert the plan contains a full action chain and ends with config write.
func TestPlanAdd_NewHomeFile_ContainsExpectedActions(t *testing.T) {
	home := t.TempDir()
	paths := appPaths{Home: home, SecureDir: filepath.Join(home, defaultEncryptedRel), InsecureDir: filepath.Join(home, defaultDecryptedRel)}
	tracked := trackedFile{
		Portable:     "$HOME/a.txt",
		HomePath:     filepath.Join(home, "a.txt"),
		InsecurePath: filepath.Join(paths.InsecureDir, "a.txt"),
		SecurePath:   filepath.Join(paths.SecureDir, "a.txt"),
		Rel:          "a.txt",
	}
	cfg := &config{ProtectedFiles: []protectedFile{}}

	p := planAdd(paths, cfg, tracked, tracked.HomePath, false, []byte("k"), AddOptions{})
	if len(p.Actions) < 6 {
		t.Fatalf("expected multiple add actions, got %d", len(p.Actions))
	}
	if p.Actions[len(p.Actions)-1].Kind != actionWriteConfig {
		t.Fatalf("expected final action write config, got %s", p.Actions[len(p.Actions)-1].Kind)
	}
}

// TestPlanAdd_RamdiskSource_SkipsCopyAction verifies RAM-origin add planning
// does not include a copy action because the plaintext already lives in RAM.
//
// How it works:
// 1. Build a tracked file that represents RAM-origin input.
// 2. Plan add with fromInsecure=true.
// 3. Assert no actionCopyFile exists in the resulting plan.
func TestPlanAdd_RamdiskSource_SkipsCopyAction(t *testing.T) {
	home := t.TempDir()
	paths := appPaths{Home: home, SecureDir: filepath.Join(home, defaultEncryptedRel), InsecureDir: filepath.Join(home, defaultDecryptedRel)}
	tracked := trackedFile{
		Portable:     "$HOME/a.txt",
		HomePath:     filepath.Join(home, "a.txt"),
		InsecurePath: filepath.Join(paths.InsecureDir, "a.txt"),
		SecurePath:   filepath.Join(paths.SecureDir, "a.txt"),
		Rel:          "a.txt",
	}

	p := planAdd(paths, &config{}, tracked, tracked.InsecurePath, true, []byte("k"), AddOptions{})
	for _, a := range p.Actions {
		if a.Kind == actionCopyFile {
			t.Fatalf("did not expect copy action for RAM-origin add")
		}
	}
}
