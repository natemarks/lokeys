package main

import (
	"errors"
	"testing"

	"github.com/google/subcommands"
)

// This module validates CLI argument and exit-code plumbing independent of
// command business logic.
//
// Test strategy:
// - directly test argument validators for 0/1/many argument combinations,
// - test runWithExitStatus mapping for usage and generic errors.

// TestRequireNoArgs_ReturnsUsageError verifies commands that take no arguments
// reject extras with usage-classified errors.
func TestRequireNoArgs_ReturnsUsageError(t *testing.T) {
	err := requireNoArgs([]string{"extra"}, "list")
	if err == nil {
		t.Fatalf("expected usage error")
	}
	if !errors.Is(err, errUsage) {
		t.Fatalf("expected errUsage, got %v", err)
	}
}

// TestRequireOneArg_ReturnsUsageErrorOnZeroOrMany verifies single-argument
// commands enforce exact cardinality.
func TestRequireOneArg_ReturnsUsageErrorOnZeroOrMany(t *testing.T) {
	if _, err := requireOneArg([]string{}, "add", "path"); err == nil {
		t.Fatalf("expected usage error for zero args")
	}
	if _, err := requireOneArg([]string{"a", "b"}, "add", "path"); err == nil {
		t.Fatalf("expected usage error for many args")
	}
}

func TestRunPauseAndUnpause_EnforceSingleArgUsage(t *testing.T) {
	if err := runPause([]string{}); err == nil || !errors.Is(err, errUsage) {
		t.Fatalf("expected pause usage error for zero args, got %v", err)
	}
	if err := runPause([]string{"a", "b"}); err == nil || !errors.Is(err, errUsage) {
		t.Fatalf("expected pause usage error for many args, got %v", err)
	}
	if err := runUnpause([]string{}); err == nil || !errors.Is(err, errUsage) {
		t.Fatalf("expected unpause usage error for zero args, got %v", err)
	}
	if err := runUnpause([]string{"a", "b"}); err == nil || !errors.Is(err, errUsage) {
		t.Fatalf("expected unpause usage error for many args, got %v", err)
	}
}

func TestUsageErrorMessages_Snapshots(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "pause missing path",
			err:  runPause([]string{}),
			want: "usage error: pause requires a single path",
		},
		{
			name: "pause too many args",
			err:  runPause([]string{"a", "b"}),
			want: "usage error: pause requires a single path",
		},
		{
			name: "unpause missing path",
			err:  runUnpause([]string{}),
			want: "usage error: unpause requires a single path",
		},
		{
			name: "list extra arg",
			err:  requireNoArgs([]string{"extra"}, "list"),
			want: "usage error: list takes no arguments",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if tc.err == nil {
				t.Fatalf("expected usage error")
			}
			if !errors.Is(tc.err, errUsage) {
				t.Fatalf("expected errUsage, got %v", tc.err)
			}
			if got := tc.err.Error(); got != tc.want {
				t.Fatalf("usage error snapshot mismatch\nwant: %q\ngot:  %q", tc.want, got)
			}
		})
	}
}

// TestRequireZeroOrOneArg_ReturnsUsageErrorOnMany verifies optional single-arg
// commands reject argument lists longer than one.
func TestRequireZeroOrOneArg_ReturnsUsageErrorOnMany(t *testing.T) {
	if _, err := requireZeroOrOneArg([]string{"a", "b"}, "restore", "archive"); err == nil {
		t.Fatalf("expected usage error for many args")
	}
	if got, err := requireZeroOrOneArg([]string{"a"}, "restore", "archive"); err != nil || got != "a" {
		t.Fatalf("expected single arg pass-through, got %q err=%v", got, err)
	}
	if got, err := requireZeroOrOneArg(nil, "restore", "archive"); err != nil || got != "" {
		t.Fatalf("expected empty arg default, got %q err=%v", got, err)
	}
}

// TestRunWithExitStatus_MapsUsageToExitUsageError verifies usage errors map to
// exit status 2 and generic errors map to exit status 1.
func TestRunWithExitStatus_MapsUsageToExitUsageError(t *testing.T) {
	if got := runWithExitStatus(usageError("bad")); got != subcommands.ExitUsageError {
		t.Fatalf("usage status mismatch: got %v", got)
	}
	if got := runWithExitStatus(errors.New("boom")); got != subcommands.ExitFailure {
		t.Fatalf("failure status mismatch: got %v", got)
	}
	if got := runWithExitStatus(nil); got != subcommands.ExitSuccess {
		t.Fatalf("success status mismatch: got %v", got)
	}
}
