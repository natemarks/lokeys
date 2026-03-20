package lokeys

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// This module validates dependency defaulting for Service construction.
//
// Test strategy:
// - construct Service with empty deps and assert defaults are populated,
// - construct Service with explicit deps and assert they are preserved.

type stubMounter struct{ called bool }

func (m *stubMounter) EnsureMounted(string) error {
	m.called = true
	return nil
}

type stubKeySource struct{}

func (stubKeySource) KeyForCommand() ([]byte, error)           { return []byte("k"), nil }
func (stubKeySource) KeyFromSessionEnv() ([]byte, bool, error) { return []byte("k"), true, nil }
func (stubKeySource) PromptForKey() ([]byte, string, error)    { return []byte("k"), "encoded-value", nil }
func (stubKeySource) PromptForNewKey() ([]byte, string, error) { return []byte("n"), "", nil }

// TestNewService_DefaultsMissingDependencies ensures nil dependency fields are
// replaced with safe defaults so command code can rely on non-nil deps.
//
// How it works:
// 1. Construct Service with empty Deps.
// 2. Assert clock, writers, mounter, and key source are all populated.
func TestNewService_DefaultsMissingDependencies(t *testing.T) {
	svc := NewService(Deps{})
	if svc.deps.Now == nil {
		t.Fatalf("expected default clock")
	}
	if svc.deps.Stdout == nil || svc.deps.Stderr == nil {
		t.Fatalf("expected default io writers")
	}
	if svc.deps.Mounter == nil {
		t.Fatalf("expected default ramdisk mounter")
	}
	if svc.deps.Keys == nil {
		t.Fatalf("expected default key source")
	}
}

// TestNewService_PreservesProvidedDependencies ensures caller-provided deps are
// not overwritten by constructor defaults.
//
// How it works:
// 1. Build explicit adapters and writer fixtures.
// 2. Construct Service with those values.
// 3. Assert Service stores the same instances.
func TestNewService_PreservesProvidedDependencies(t *testing.T) {
	now := func() time.Time { return time.Unix(1, 0) }
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	mounter := &stubMounter{}
	keys := stubKeySource{}
	paths := PathOverrides{Home: "/tmp/home", ConfigPath: "/tmp/cfg/lokeys.json", SecureDir: "/tmp/secure", InsecureDir: "/tmp/insecure"}

	svc := NewService(Deps{Now: now, Stdout: stdout, Stderr: stderr, Mounter: mounter, Keys: keys, Paths: paths})
	if svc.deps.Now() != now() {
		t.Fatalf("expected provided clock")
	}
	if svc.deps.Stdout != stdout || svc.deps.Stderr != stderr {
		t.Fatalf("expected provided writers")
	}
	if svc.deps.Mounter != mounter {
		t.Fatalf("expected provided mounter")
	}
	if svc.deps.Paths != paths {
		t.Fatalf("expected provided paths")
	}
}

// TestServiceRunList_UsesInjectedMountAndOutput verifies command orchestration
// can run through Service with injected dependencies instead of package globals.
//
// How it works:
// 1. Inject a tracking mounter and buffer-backed stdout.
// 2. Run list in a temp HOME first-run state.
// 3. Assert injected mounter was called and output contains init message.
func TestServiceRunList_UsesInjectedMountAndOutput(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	stdout := &bytes.Buffer{}
	mounter := &stubMounter{}
	svc := NewService(Deps{Stdout: stdout, Mounter: mounter, Keys: stubKeySource{}})

	if err := svc.RunList(); err != nil {
		t.Fatalf("RunList: %v", err)
	}
	if !mounter.called {
		t.Fatalf("expected injected mount function to be called")
	}
	if !strings.Contains(stdout.String(), "No protected files found.") {
		t.Fatalf("expected initialization output, got: %q", stdout.String())
	}
}

// TestServiceRunSessionExport_UsesInjectedPrompt verifies session-export uses
// the prompt dependency provided on Service rather than direct terminal input.
//
// How it works:
// 1. Inject a key source with deterministic PromptForKey output.
// 2. Run session-export.
// 3. Assert resulting export line contains the injected encoded key.
func TestServiceRunSessionExport_UsesInjectedPrompt(t *testing.T) {
	svc := NewService(Deps{Keys: stubKeySource{}})

	line, err := svc.RunSessionExport()
	if err != nil {
		t.Fatalf("RunSessionExport: %v", err)
	}
	if line != "export "+SessionKeyEnv+"='encoded-value'" {
		t.Fatalf("unexpected export line: %q", line)
	}
}
