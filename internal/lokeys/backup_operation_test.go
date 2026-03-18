package lokeys

import (
	"os"
	"path/filepath"
	"testing"
)

// This module validates backup command orchestration behavior beyond raw tar
// creation helpers, including pre-backup enrollment of external RAM files.

// TestRunBackup_EnrollsUntrackedInsecureFilesBeforeArchive verifies backup
// promotes untracked insecure files to protected content before archiving.
//
// How it works:
// 1. Create an empty config and an external file under ~/.lokeys/insecure.
// 2. Run backup through Service with a valid session key.
// 3. Assert config enrollment, secure copy, home symlink, and tar entry.
func TestRunBackup_EnrollsUntrackedInsecureFilesBeforeArchive(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	_, encoded := mustEncodedSessionKey(t)
	t.Setenv(SessionKeyEnv, encoded)

	if _, _, err := ensureConfig(); err != nil {
		t.Fatalf("ensure config: %v", err)
	}
	insecurePath := filepath.Join(home, defaultDecryptedRel, "backup-new", "note.txt")
	if err := os.MkdirAll(filepath.Dir(insecurePath), dirPerm); err != nil {
		t.Fatalf("mkdir insecure parent: %v", err)
	}
	if err := os.WriteFile(insecurePath, []byte("backup-data\n"), 0600); err != nil {
		t.Fatalf("write insecure file: %v", err)
	}

	svc := newTestService()
	backupPath, err := svc.RunBackup()
	if err != nil {
		t.Fatalf("RunBackup: %v", err)
	}

	cfg, err := readConfig(filepath.Join(home, configFileRel))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !containsString(cfg.ProtectedFiles, "$HOME/backup-new/note.txt") {
		t.Fatalf("expected enrolled config entry, got %#v", cfg.ProtectedFiles)
	}

	securePath := filepath.Join(home, defaultEncryptedRel, "backup-new", "note.txt")
	if !fileExists(securePath) {
		t.Fatalf("expected secure file at %s", securePath)
	}
	homePath := filepath.Join(home, "backup-new", "note.txt")
	info, err := os.Lstat(homePath)
	if err != nil {
		t.Fatalf("lstat home path: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected symlink at %s", homePath)
	}

	names, err := listTarGzEntries(backupPath)
	if err != nil {
		t.Fatalf("list tar entries: %v", err)
	}
	if !containsString(names, "backup-new/note.txt") {
		t.Fatalf("expected discovered file in backup archive, entries=%#v", names)
	}
}
