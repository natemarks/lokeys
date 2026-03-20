package lokeys

import (
	"path/filepath"
	"testing"
)

func TestResolveAppPaths_DefaultsFromHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(HomeDirEnv, "")
	t.Setenv(ConfigPathEnv, "")
	t.Setenv(SecureDirEnv, "")
	t.Setenv(InsecureDirEnv, "")

	paths, err := resolveAppPaths(PathOverrides{})
	if err != nil {
		t.Fatalf("resolveAppPaths: %v", err)
	}

	if paths.Home != home {
		t.Fatalf("home mismatch: got %s want %s", paths.Home, home)
	}
	if paths.ConfigPath != filepath.Join(home, configFileRel) {
		t.Fatalf("config mismatch: got %s", paths.ConfigPath)
	}
	if paths.SecureDir != filepath.Join(home, defaultEncryptedRel) {
		t.Fatalf("secure mismatch: got %s", paths.SecureDir)
	}
	if paths.InsecureDir != filepath.Join(home, defaultDecryptedRel) {
		t.Fatalf("insecure mismatch: got %s", paths.InsecureDir)
	}
}

func TestResolveAppPaths_FullOverrides(t *testing.T) {
	home := t.TempDir()
	cfgPath := filepath.Join(t.TempDir(), "lokeys.json")
	secure := t.TempDir()
	insecure := t.TempDir()

	paths, err := resolveAppPaths(PathOverrides{
		Home:        home,
		ConfigPath:  cfgPath,
		SecureDir:   secure,
		InsecureDir: insecure,
	})
	if err != nil {
		t.Fatalf("resolveAppPaths: %v", err)
	}

	if paths.Home != home || paths.ConfigPath != cfgPath || paths.SecureDir != secure || paths.InsecureDir != insecure {
		t.Fatalf("unexpected resolved paths: %#v", paths)
	}
}

func TestResolveAppPaths_PartialOverridesRejected(t *testing.T) {
	_, err := resolveAppPaths(PathOverrides{ConfigPath: filepath.Join(t.TempDir(), "lokeys.json")})
	if err == nil {
		t.Fatalf("expected partial override error")
	}
}

func TestResolveAppPaths_RejectsRelativeOverride(t *testing.T) {
	_, err := resolveAppPaths(PathOverrides{
		ConfigPath:  "./lokeys.json",
		SecureDir:   t.TempDir(),
		InsecureDir: t.TempDir(),
	})
	if err == nil {
		t.Fatalf("expected relative override error")
	}
}

func TestResolveAppPaths_ServiceDepsOverride(t *testing.T) {
	home := t.TempDir()
	cfgPath := filepath.Join(t.TempDir(), "lokeys.json")
	secure := t.TempDir()
	insecure := t.TempDir()

	svc := NewService(Deps{Paths: PathOverrides{Home: home, ConfigPath: cfgPath, SecureDir: secure, InsecureDir: insecure}})
	paths, err := svc.appPaths()
	if err != nil {
		t.Fatalf("appPaths: %v", err)
	}
	if paths.Home != home || paths.ConfigPath != cfgPath || paths.SecureDir != secure || paths.InsecureDir != insecure {
		t.Fatalf("unexpected resolved service paths: %#v", paths)
	}
}
