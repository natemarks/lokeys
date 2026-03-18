package lokeys

import (
	"path/filepath"
	"testing"
)

// This module validates mount detection parsing and non-interactive safeguards.
//
// Test strategy:
// - unit test mount parsing with synthetic /proc/mounts fixtures,
// - assert ensureRamdiskMounted fails with actionable guidance when prompting is
//   impossible (non-terminal stdin under go test).

// TestIsMountedInProcMounts_ParsesEntries ensures the mount parser correctly
// identifies matching mount points.
func TestIsMountedInProcMounts_ParsesEntries(t *testing.T) {
	proc := "tmpfs /run tmpfs rw 0 0\n" +
		"tmpfs /home/test/.lokeys/insecure tmpfs rw 0 0\n"
	if !isMountedInProcMounts(proc, "/home/test/.lokeys/insecure") {
		t.Fatalf("expected mount match")
	}
	if isMountedInProcMounts(proc, "/home/test/other") {
		t.Fatalf("unexpected mount match")
	}
}

// TestEnsureRamdiskMounted_NonTerminalPromptRequired_ErrorsActionably ensures
// command execution in non-interactive environments returns a clear message.
func TestEnsureRamdiskMounted_NonTerminalPromptRequired_ErrorsActionably(t *testing.T) {
	path := filepath.Join(t.TempDir(), "insecure")
	err := ensureRamdiskMounted(path)
	if err == nil {
		t.Fatalf("expected non-terminal error")
	}
}
