package lokeys

import (
	"path/filepath"
	"testing"
)

// TestBuildTrackedFileFromPortable_ValidHomePath verifies that a portable
// config entry is expanded into consistent home/secure/insecure absolute paths.
//
// How it works:
// 1. Build an isolated HOME fixture.
// 2. Resolve a $HOME-based portable path.
// 3. Assert each derived field maps to the expected canonical locations.
func TestBuildTrackedFileFromPortable_ValidHomePath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	secureDir := filepath.Join(home, defaultEncryptedRel)
	insecureDir := filepath.Join(home, defaultDecryptedRel)

	tracked, err := buildTrackedFileFromPortable(home, secureDir, insecureDir, "$HOME/docs/a.txt")
	if err != nil {
		t.Fatalf("buildTrackedFileFromPortable: %v", err)
	}
	if tracked.Rel != filepath.Join("docs", "a.txt") {
		t.Fatalf("rel mismatch: got %q", tracked.Rel)
	}
	if tracked.HomePath != filepath.Join(home, "docs", "a.txt") {
		t.Fatalf("home path mismatch: got %q", tracked.HomePath)
	}
	if tracked.SecurePath != filepath.Join(secureDir, "docs", "a.txt") {
		t.Fatalf("secure path mismatch: got %q", tracked.SecurePath)
	}
	if tracked.InsecurePath != filepath.Join(insecureDir, "docs", "a.txt") {
		t.Fatalf("insecure path mismatch: got %q", tracked.InsecurePath)
	}
}

// TestBuildTrackedFileFromPortable_RejectsOutsideHome ensures path validation
// is enforced when a portable path resolves outside HOME.
//
// How it works:
// 1. Use a path that does not expand under HOME.
// 2. Expect the helper to return the same safety guard message used by path logic.
func TestBuildTrackedFileFromPortable_RejectsOutsideHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	secureDir := filepath.Join(home, defaultEncryptedRel)
	insecureDir := filepath.Join(home, defaultDecryptedRel)

	_, err := buildTrackedFileFromPortable(home, secureDir, insecureDir, "/tmp/not-home.txt")
	if err == nil {
		t.Fatalf("expected outside-home error")
	}
}

// TestBuildTrackedFileFromInsecurePath_DetectsRamdiskOrigin verifies that a
// path under the RAM-disk root is detected and mapped back to its canonical
// home path and portable form.
//
// How it works:
// 1. Build a file path under insecureDir.
// 2. Resolve with buildTrackedFileFromInsecurePath.
// 3. Assert fromInsecure=true and each derived field is correct.
func TestBuildTrackedFileFromInsecurePath_DetectsRamdiskOrigin(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	secureDir := filepath.Join(home, defaultEncryptedRel)
	insecureDir := filepath.Join(home, defaultDecryptedRel)
	full := filepath.Join(insecureDir, "notes", "ram.txt")

	tracked, fromInsecure, err := buildTrackedFileFromInsecurePath(home, secureDir, insecureDir, full)
	if err != nil {
		t.Fatalf("buildTrackedFileFromInsecurePath: %v", err)
	}
	if !fromInsecure {
		t.Fatalf("expected fromInsecure=true")
	}
	if tracked.HomePath != filepath.Join(home, "notes", "ram.txt") {
		t.Fatalf("home path mismatch: got %q", tracked.HomePath)
	}
	if tracked.Portable != "$HOME/notes/ram.txt" {
		t.Fatalf("portable mismatch: got %q", tracked.Portable)
	}
}

// TestBuildTrackedFileFromInsecurePath_NonRamdiskReturnsFalse confirms the
// helper returns a clean "not from insecure root" signal instead of an error.
//
// How it works:
// 1. Provide a home path outside insecureDir.
// 2. Assert fromInsecure=false and no error.
func TestBuildTrackedFileFromInsecurePath_NonRamdiskReturnsFalse(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	secureDir := filepath.Join(home, defaultEncryptedRel)
	insecureDir := filepath.Join(home, defaultDecryptedRel)
	full := filepath.Join(home, "notes", "plain.txt")

	_, fromInsecure, err := buildTrackedFileFromInsecurePath(home, secureDir, insecureDir, full)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fromInsecure {
		t.Fatalf("expected fromInsecure=false")
	}
}

// TestBuildTrackedFileFromHomePath_ComputesSecureAndInsecurePaths verifies
// the helper normalizes a home file path into all canonical storage locations.
//
// How it works:
// 1. Build an absolute path under HOME.
// 2. Resolve to trackedFile.
// 3. Assert rel, portable path, secure path, and insecure path values.
func TestBuildTrackedFileFromHomePath_ComputesSecureAndInsecurePaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	secureDir := filepath.Join(home, defaultEncryptedRel)
	insecureDir := filepath.Join(home, defaultDecryptedRel)

	tracked, err := buildTrackedFileFromHomePath(home, secureDir, insecureDir, filepath.Join(home, "x", "y.txt"))
	if err != nil {
		t.Fatalf("buildTrackedFileFromHomePath: %v", err)
	}
	if tracked.Rel != filepath.Join("x", "y.txt") {
		t.Fatalf("rel mismatch: got %q", tracked.Rel)
	}
	if tracked.Portable != "$HOME/x/y.txt" {
		t.Fatalf("portable mismatch: got %q", tracked.Portable)
	}
	if tracked.SecurePath != filepath.Join(secureDir, "x", "y.txt") {
		t.Fatalf("secure mismatch: got %q", tracked.SecurePath)
	}
	if tracked.InsecurePath != filepath.Join(insecureDir, "x", "y.txt") {
		t.Fatalf("insecure mismatch: got %q", tracked.InsecurePath)
	}
}
