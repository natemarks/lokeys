package lokeys

import "testing"

// This module validates unseal planning, ensuring each tracked file maps to a
// deterministic decrypt+symlink action sequence.

// TestPlanUnseal_DecryptAndSymlinkActions verifies a single tracked entry
// produces exactly ensure-parent, decrypt, and symlink actions in that order.
//
// How it works:
// 1. Create one tracked file fixture.
// 2. Build an unseal plan.
// 3. Assert strict action count and ordering for deterministic execution.
func TestPlanUnseal_DecryptAndSymlinkActions(t *testing.T) {
	tracked := []trackedFile{{HomePath: "/home/u/a.txt", InsecurePath: "/ram/a.txt", SecurePath: "/secure/a.txt"}}
	p := planUnseal(&config{}, tracked, []byte("k"))
	if len(p.Actions) != 3 {
		t.Fatalf("expected 3 actions, got %d", len(p.Actions))
	}
	if p.Actions[0].Kind != actionEnsureParentDir || p.Actions[1].Kind != actionDecryptFile || p.Actions[2].Kind != actionReplaceWithSymlink {
		t.Fatalf("unexpected unseal action order")
	}
}
