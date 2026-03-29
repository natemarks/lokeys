package lokeys

import (
	"bytes"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunPause_SetsPausedTrue(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if _, _, err := ensureConfig(); err != nil {
		t.Fatalf("ensure config: %v", err)
	}
	portable := "$HOME/docs/a.txt"
	if err := writeConfig(&config{ProtectedFiles: protectedFilesFromPaths([]string{portable})}); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var out bytes.Buffer
	svc := NewService(Deps{Stdout: &out, Stderr: io.Discard, Mounter: testMounter{}, Keys: testKeySource{}})
	if err := svc.RunPause(filepath.Join(home, "docs", "a.txt")); err != nil {
		t.Fatalf("RunPause: %v", err)
	}

	cfg, err := readConfig(filepath.Join(home, configFileRel))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	idx := cfg.protectedFileIndex(portable)
	if idx == -1 {
		t.Fatalf("missing protected entry: %#v", cfg.ProtectedFiles)
	}
	if !cfg.ProtectedFiles[idx].Paused {
		t.Fatalf("expected paused=true for %s", portable)
	}
	if !strings.Contains(out.String(), "paused "+portable) {
		t.Fatalf("expected paused output, got %q", out.String())
	}
}

func TestRunUnpause_SetsPausedFalse(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if _, _, err := ensureConfig(); err != nil {
		t.Fatalf("ensure config: %v", err)
	}
	portable := "$HOME/docs/b.txt"
	if err := writeConfig(&config{ProtectedFiles: []protectedFile{{Path: portable, Paused: true}}}); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var out bytes.Buffer
	svc := NewService(Deps{Stdout: &out, Stderr: io.Discard, Mounter: testMounter{}, Keys: testKeySource{}})
	if err := svc.RunUnpause(filepath.Join(home, "docs", "b.txt")); err != nil {
		t.Fatalf("RunUnpause: %v", err)
	}

	cfg, err := readConfig(filepath.Join(home, configFileRel))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	idx := cfg.protectedFileIndex(portable)
	if idx == -1 {
		t.Fatalf("missing protected entry: %#v", cfg.ProtectedFiles)
	}
	if cfg.ProtectedFiles[idx].Paused {
		t.Fatalf("expected paused=false for %s", portable)
	}
	if !strings.Contains(out.String(), "unpaused "+portable) {
		t.Fatalf("expected unpaused output, got %q", out.String())
	}
}

func TestRunPauseAndRunUnpause_NonManagedPathReturnsSuccess(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if _, _, err := ensureConfig(); err != nil {
		t.Fatalf("ensure config: %v", err)
	}

	var out bytes.Buffer
	svc := NewService(Deps{Stdout: &out, Stderr: io.Discard, Mounter: testMounter{}, Keys: testKeySource{}})
	target := filepath.Join(home, "docs", "missing.txt")

	if err := svc.RunPause(target); err != nil {
		t.Fatalf("RunPause unexpected error: %v", err)
	}
	if err := svc.RunUnpause(target); err != nil {
		t.Fatalf("RunUnpause unexpected error: %v", err)
	}

	portable := "$HOME/docs/missing.txt"
	if !strings.Contains(out.String(), portable+" is not protected.") {
		t.Fatalf("expected not-protected message, got %q", out.String())
	}
}

func TestRunPauseAndUnpause_AreIdempotent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if _, _, err := ensureConfig(); err != nil {
		t.Fatalf("ensure config: %v", err)
	}
	portable := "$HOME/docs/idempotent.txt"
	if err := writeConfig(&config{ProtectedFiles: []protectedFile{{Path: portable, Paused: false}}}); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var out bytes.Buffer
	svc := NewService(Deps{Stdout: &out, Stderr: io.Discard, Mounter: testMounter{}, Keys: testKeySource{}})
	pathArg := filepath.Join(home, "docs", "idempotent.txt")

	if err := svc.RunPause(pathArg); err != nil {
		t.Fatalf("first RunPause: %v", err)
	}
	if err := svc.RunPause(pathArg); err != nil {
		t.Fatalf("second RunPause: %v", err)
	}

	cfgAfterPause, err := readConfig(filepath.Join(home, configFileRel))
	if err != nil {
		t.Fatalf("read config after pause: %v", err)
	}
	idx := cfgAfterPause.protectedFileIndex(portable)
	if idx == -1 || !cfgAfterPause.ProtectedFiles[idx].Paused {
		t.Fatalf("expected paused=true after idempotent pause calls, got %#v", cfgAfterPause.ProtectedFiles)
	}

	if err := svc.RunUnpause(pathArg); err != nil {
		t.Fatalf("first RunUnpause: %v", err)
	}
	if err := svc.RunUnpause(pathArg); err != nil {
		t.Fatalf("second RunUnpause: %v", err)
	}

	cfgAfterUnpause, err := readConfig(filepath.Join(home, configFileRel))
	if err != nil {
		t.Fatalf("read config after unpause: %v", err)
	}
	idx = cfgAfterUnpause.protectedFileIndex(portable)
	if idx == -1 || cfgAfterUnpause.ProtectedFiles[idx].Paused {
		t.Fatalf("expected paused=false after idempotent unpause calls, got %#v", cfgAfterUnpause.ProtectedFiles)
	}

	outStr := out.String()
	if !strings.Contains(outStr, portable+" already paused.") {
		t.Fatalf("expected already-paused message, got %q", outStr)
	}
	if !strings.Contains(outStr, portable+" already unpaused.") {
		t.Fatalf("expected already-unpaused message, got %q", outStr)
	}
}
