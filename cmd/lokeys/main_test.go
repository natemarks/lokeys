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
