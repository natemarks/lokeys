package lokeys

import (
	"os"
	"path/filepath"
	"testing"
)

// This module validates plan execution behavior for success and failure paths.

// TestApplyPlan_ExecutesActionsInOrder verifies action application creates a
// copied file when ensure-parent and copy actions are provided in sequence.
//
// How it works:
// 1. Create a source file and a destination path with a missing parent.
// 2. Execute ensure-parent then copy actions.
// 3. Assert destination file exists, proving ordered execution.
func TestApplyPlan_ExecutesActionsInOrder(t *testing.T) {
	svc := newTestService()
	root := t.TempDir()
	src := filepath.Join(root, "src.txt")
	dst := filepath.Join(root, "nested", "dst.txt")
	if err := os.WriteFile(src, []byte("x"), 0600); err != nil {
		t.Fatalf("write src: %v", err)
	}

	p := plan{Actions: []action{
		{Kind: actionEnsureParentDir, Path: dst},
		{Kind: actionCopyFile, Source: src, Path: dst, Perm: 0600},
	}}
	if err := svc.applyPlan(p); err != nil {
		t.Fatalf("applyPlan: %v", err)
	}
	if !fileExists(dst) {
		t.Fatalf("expected copied destination file")
	}
}

// TestApplyPlan_StopsOnFirstFailure verifies executor stops processing when an
// action fails and does not apply subsequent actions.
//
// How it works:
// 1. Build a plan where the first copy action must fail.
// 2. Add a second action that would create a later directory.
// 3. Assert error is returned and later directory is never created.
func TestApplyPlan_StopsOnFirstFailure(t *testing.T) {
	svc := newTestService()
	root := t.TempDir()
	dst := filepath.Join(root, "later", "dst.txt")

	p := plan{Actions: []action{
		{Kind: actionCopyFile, Source: filepath.Join(root, "missing.txt"), Path: filepath.Join(root, "nope", "x.txt"), Perm: 0600},
		{Kind: actionEnsureParentDir, Path: dst},
	}}
	err := svc.applyPlan(p)
	if err == nil {
		t.Fatalf("expected execution error")
	}
	if fileExists(filepath.Join(root, "later")) {
		t.Fatalf("expected later action not to run")
	}
}
