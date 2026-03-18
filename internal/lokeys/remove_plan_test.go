package lokeys

import "testing"

// This module validates remove planning and expected cleanup sequence.

// TestPlanRemove_ManagedSymlink_RestoreAndCleanupActions verifies removal
// includes restore, secure/insecure cleanup, and config write actions.
//
// How it works:
// 1. Build config and tracked-file fixtures for a protected path.
// 2. Build the remove plan for index 0.
// 3. Assert the plan starts with restore and ends with config persistence.
func TestPlanRemove_ManagedSymlink_RestoreAndCleanupActions(t *testing.T) {
	cfg := &config{ProtectedFiles: []string{"$HOME/a.txt", "$HOME/b.txt"}}
	tracked := trackedFile{HomePath: "/home/u/a.txt", InsecurePath: "/ram/a.txt", SecurePath: "/secure/a.txt"}
	p := planRemove(cfg, 0, tracked)
	if len(p.Actions) != 4 {
		t.Fatalf("expected 4 actions, got %d", len(p.Actions))
	}
	if p.Actions[0].Kind != actionRestoreManagedLink || p.Actions[3].Kind != actionWriteConfig {
		t.Fatalf("unexpected remove action sequence")
	}
}
