package lokeys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This module exercises end-to-end command orchestration for add/seal flows
// using a temp HOME and a stubbed RAM-disk mount function.
//
// Test strategy:
// - keep crypto real to validate secure artifacts actually decrypt,
// - stub only mount interaction to avoid sudo/terminal coupling,
// - assert both filesystem side effects and config mutations.

// TestRunAddProtectsRamdiskCreatedFile verifies that adding a file created
// directly in the RAM-disk tree creates the derived home symlink, encrypted
// copy, and config enrollment entry.
func TestRunAddProtectsRamdiskCreatedFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	_, encoded := mustEncodedSessionKey(t)
	t.Setenv(SessionKeyEnv, encoded)

	svc := newTestService()

	insecurePath := filepath.Join(home, defaultDecryptedRel, "notes", "new.txt")
	if err := os.MkdirAll(filepath.Dir(insecurePath), dirPerm); err != nil {
		t.Fatalf("mkdir insecure parent: %v", err)
	}
	if err := os.WriteFile(insecurePath, []byte("secret\n"), 0600); err != nil {
		t.Fatalf("write insecure file: %v", err)
	}

	if err := svc.RunAdd(insecurePath); err != nil {
		t.Fatalf("RunAdd failed: %v", err)
	}

	homePath := filepath.Join(home, "notes", "new.txt")
	info, err := os.Lstat(homePath)
	if err != nil {
		t.Fatalf("stat home path: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected symlink at %s", homePath)
	}
	target, err := os.Readlink(homePath)
	if err != nil {
		t.Fatalf("read symlink: %v", err)
	}
	if target != insecurePath {
		t.Fatalf("symlink target mismatch: got %s want %s", target, insecurePath)
	}

	securePath := filepath.Join(home, defaultEncryptedRel, "notes", "new.txt")
	if !fileExists(securePath) {
		t.Fatalf("expected secure file at %s", securePath)
	}

	cfg, err := readConfig(filepath.Join(home, configFileRel))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !cfg.hasProtectedFile("$HOME/notes/new.txt") {
		t.Fatalf("missing protected file entry: %#v", cfg.ProtectedFiles)
	}
}

// TestRunAddFailsWhenDerivedHomePathExists verifies conflict protection for
// RAM-origin files: if the derived canonical home path already exists, add must
// fail before any enrollment mutation.
func TestRunAddFailsWhenDerivedHomePathExists(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	_, encoded := mustEncodedSessionKey(t)
	t.Setenv(SessionKeyEnv, encoded)

	svc := newTestService()

	insecurePath := filepath.Join(home, defaultDecryptedRel, "notes", "conflict.txt")
	if err := os.MkdirAll(filepath.Dir(insecurePath), dirPerm); err != nil {
		t.Fatalf("mkdir insecure parent: %v", err)
	}
	if err := os.WriteFile(insecurePath, []byte("secret\n"), 0600); err != nil {
		t.Fatalf("write insecure file: %v", err)
	}

	homePath := filepath.Join(home, "notes", "conflict.txt")
	if err := os.MkdirAll(filepath.Dir(homePath), dirPerm); err != nil {
		t.Fatalf("mkdir home parent: %v", err)
	}
	if err := os.WriteFile(homePath, []byte("existing\n"), 0600); err != nil {
		t.Fatalf("write home file: %v", err)
	}

	err := svc.RunAdd(insecurePath)
	if err == nil {
		t.Fatalf("expected conflict error")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected exists error, got: %v", err)
	}
}

// TestRunSealDiscoversAndProtectsRamdiskFiles verifies seal auto-discovers
// untracked regular files in the RAM-disk tree and promotes them into managed
// protection state (encrypted file + symlink + config entry).
func TestRunSealDiscoversAndProtectsRamdiskFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	_, encoded := mustEncodedSessionKey(t)
	t.Setenv(SessionKeyEnv, encoded)

	svc := newTestService()

	if _, _, err := ensureConfig(); err != nil {
		t.Fatalf("ensure config: %v", err)
	}

	insecurePath := filepath.Join(home, defaultDecryptedRel, "notes", "seal-new.txt")
	if err := os.MkdirAll(filepath.Dir(insecurePath), dirPerm); err != nil {
		t.Fatalf("mkdir insecure parent: %v", err)
	}
	if err := os.WriteFile(insecurePath, []byte("secret\n"), 0600); err != nil {
		t.Fatalf("write insecure file: %v", err)
	}

	if err := svc.RunSeal(); err != nil {
		t.Fatalf("RunSeal failed: %v", err)
	}

	homePath := filepath.Join(home, "notes", "seal-new.txt")
	info, err := os.Lstat(homePath)
	if err != nil {
		t.Fatalf("stat home path: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected symlink at %s", homePath)
	}

	securePath := filepath.Join(home, defaultEncryptedRel, "notes", "seal-new.txt")
	if !fileExists(securePath) {
		t.Fatalf("expected secure file at %s", securePath)
	}

	cfg, err := readConfig(filepath.Join(home, configFileRel))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !cfg.hasProtectedFile("$HOME/notes/seal-new.txt") {
		t.Fatalf("missing protected file entry: %#v", cfg.ProtectedFiles)
	}
}

// TestRunSealFailsFastOnFirstConflict verifies fail-fast semantics during
// discovery: if any RAM-disk file maps to an already-existing home path, seal
// aborts and does not partially protect unrelated files.
func TestRunSealFailsFastOnFirstConflict(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	_, encoded := mustEncodedSessionKey(t)
	t.Setenv(SessionKeyEnv, encoded)

	svc := newTestService()

	if _, _, err := ensureConfig(); err != nil {
		t.Fatalf("ensure config: %v", err)
	}

	conflictRAMPath := filepath.Join(home, defaultDecryptedRel, "a", "conflict.txt")
	safeRAMPath := filepath.Join(home, defaultDecryptedRel, "b", "safe.txt")
	if err := os.MkdirAll(filepath.Dir(conflictRAMPath), dirPerm); err != nil {
		t.Fatalf("mkdir conflict parent: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(safeRAMPath), dirPerm); err != nil {
		t.Fatalf("mkdir safe parent: %v", err)
	}
	if err := os.WriteFile(conflictRAMPath, []byte("conflict\n"), 0600); err != nil {
		t.Fatalf("write conflict file: %v", err)
	}
	if err := os.WriteFile(safeRAMPath, []byte("safe\n"), 0600); err != nil {
		t.Fatalf("write safe file: %v", err)
	}

	homeConflictPath := filepath.Join(home, "a", "conflict.txt")
	if err := os.MkdirAll(filepath.Dir(homeConflictPath), dirPerm); err != nil {
		t.Fatalf("mkdir home conflict parent: %v", err)
	}
	if err := os.WriteFile(homeConflictPath, []byte("existing\n"), 0600); err != nil {
		t.Fatalf("write home conflict file: %v", err)
	}

	err := svc.RunSeal()
	if err == nil {
		t.Fatalf("expected conflict error")
	}
	if !strings.Contains(err.Error(), "refusing to seal RAM-disk file") {
		t.Fatalf("unexpected error: %v", err)
	}

	safeHomePath := filepath.Join(home, "b", "safe.txt")
	if fileExists(safeHomePath) {
		t.Fatalf("expected no symlink at %s on conflict", safeHomePath)
	}

	safeSecurePath := filepath.Join(home, defaultEncryptedRel, "b", "safe.txt")
	if fileExists(safeSecurePath) {
		t.Fatalf("expected no secure file at %s on conflict", safeSecurePath)
	}

	cfg, err := readConfig(filepath.Join(home, configFileRel))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if len(cfg.ProtectedFiles) != 0 {
		t.Fatalf("expected unchanged config, got %#v", cfg.ProtectedFiles)
	}
}

// TestRunSeal_DoesNotFailWhenManagedInsecureMissing verifies seal tolerates
// managed entries that are absent from RAM-disk and still seals present files.
func TestRunSeal_DoesNotFailWhenManagedInsecureMissing(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	key, encoded := mustEncodedSessionKey(t)
	t.Setenv(SessionKeyEnv, encoded)

	presentPortable := "$HOME/docs/present.txt"
	missingPortable := "$HOME/docs/missing.txt"
	if _, _, err := ensureConfig(); err != nil {
		t.Fatalf("ensure config: %v", err)
	}
	if err := writeConfig(&config{ProtectedFiles: protectedFilesFromPaths([]string{presentPortable, missingPortable})}); err != nil {
		t.Fatalf("write config: %v", err)
	}

	presentInsecure := filepath.Join(home, defaultDecryptedRel, "docs", "present.txt")
	if err := os.MkdirAll(filepath.Dir(presentInsecure), dirPerm); err != nil {
		t.Fatalf("mkdir present insecure parent: %v", err)
	}
	if err := os.WriteFile(presentInsecure, []byte("present-updated\n"), 0600); err != nil {
		t.Fatalf("write present insecure file: %v", err)
	}

	missingSecure := filepath.Join(home, defaultEncryptedRel, "docs", "missing.txt")
	if err := os.MkdirAll(filepath.Dir(missingSecure), dirPerm); err != nil {
		t.Fatalf("mkdir missing secure parent: %v", err)
	}
	originalMissingCiphertext, err := encryptBytes([]byte("missing-original\n"), key)
	if err != nil {
		t.Fatalf("encrypt missing secure baseline: %v", err)
	}
	if err := os.WriteFile(missingSecure, originalMissingCiphertext, 0600); err != nil {
		t.Fatalf("write missing secure baseline: %v", err)
	}

	svc := newTestService()
	if err := svc.RunSeal(); err != nil {
		t.Fatalf("RunSeal failed with missing managed insecure file: %v", err)
	}

	presentSecure := filepath.Join(home, defaultEncryptedRel, "docs", "present.txt")
	presentCiphertext, err := os.ReadFile(presentSecure)
	if err != nil {
		t.Fatalf("read present secure file: %v", err)
	}
	presentPlaintext, err := decryptBytes(presentCiphertext, key)
	if err != nil {
		t.Fatalf("decrypt present secure file: %v", err)
	}
	if string(presentPlaintext) != "present-updated\n" {
		t.Fatalf("unexpected present secure plaintext: %q", string(presentPlaintext))
	}

	currentMissingCiphertext, err := os.ReadFile(missingSecure)
	if err != nil {
		t.Fatalf("read missing secure file: %v", err)
	}
	if string(currentMissingCiphertext) != string(originalMissingCiphertext) {
		t.Fatalf("expected missing secure file to remain unchanged")
	}
}

// TestRunAdd_AWSCredentialsAutoBypassWithoutFlag verifies ~/.aws/credentials
// is auto-bypassed from KMS when KMS is enabled.
func TestRunAdd_AWSCredentialsAutoBypassWithoutFlag(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	_, encoded := mustEncodedSessionKey(t)
	t.Setenv(SessionKeyEnv, encoded)

	svc := newTestService()
	if _, _, err := ensureConfig(); err != nil {
		t.Fatalf("ensure config: %v", err)
	}
	if err := writeConfig(newConfigFixtureBuilder().WithKMSEnabled("alias/lokeys", "us-east-1").Build()); err != nil {
		t.Fatalf("write config: %v", err)
	}

	awsCreds := filepath.Join(home, ".aws", "credentials")
	if err := os.MkdirAll(filepath.Dir(awsCreds), dirPerm); err != nil {
		t.Fatalf("mkdir aws dir: %v", err)
	}
	if err := os.WriteFile(awsCreds, []byte("[default]\naws_access_key_id=test\n"), 0600); err != nil {
		t.Fatalf("write aws credentials: %v", err)
	}

	if err := svc.RunAdd(awsCreds); err != nil {
		t.Fatalf("RunAdd failed: %v", err)
	}

	cfg, err := readConfig(filepath.Join(home, configFileRel))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !containsString(cfg.KMSBypassFiles, filepath.Join("$HOME", ".aws", "credentials")) {
		t.Fatalf("expected aws credentials auto-bypass entry, got %#v", cfg.KMSBypassFiles)
	}

	securePath := filepath.Join(home, defaultEncryptedRel, ".aws", "credentials")
	ciphertext, err := os.ReadFile(securePath)
	if err != nil {
		t.Fatalf("read secure file: %v", err)
	}
	if !strings.HasPrefix(string(ciphertext), fileMagicV2) {
		t.Fatalf("expected non-kms ciphertext, got %q", string(ciphertext[:len(fileMagicV2)]))
	}
}

// TestRunAdd_AWSNonDefaultPathStillRequiresExplicitBypass verifies only default
// AWS config files auto-bypass KMS; other ~/.aws files remain fail-closed.
func TestRunAdd_AWSNonDefaultPathStillRequiresExplicitBypass(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	_, encoded := mustEncodedSessionKey(t)
	t.Setenv(SessionKeyEnv, encoded)

	svc := newTestService()
	if _, _, err := ensureConfig(); err != nil {
		t.Fatalf("ensure config: %v", err)
	}
	if err := writeConfig(newConfigFixtureBuilder().WithKMSEnabled("alias/lokeys", "us-east-1").Build()); err != nil {
		t.Fatalf("write config: %v", err)
	}

	awsToken := filepath.Join(home, ".aws", "sso", "cache", "token.json")
	if err := os.MkdirAll(filepath.Dir(awsToken), dirPerm); err != nil {
		t.Fatalf("mkdir aws dir: %v", err)
	}
	if err := os.WriteFile(awsToken, []byte("{\"accessToken\":\"test\"}\n"), 0600); err != nil {
		t.Fatalf("write aws token: %v", err)
	}

	err := svc.RunAdd(awsToken)
	if err == nil {
		t.Fatalf("expected aws dependency loop error")
	}
	if !strings.Contains(err.Error(), "dependency loop") {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := svc.RunAddWithOptions(awsToken, AddOptions{AllowKMSBypass: true}); err != nil {
		t.Fatalf("RunAddWithOptions failed: %v", err)
	}

	cfg, err := readConfig(filepath.Join(home, configFileRel))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !containsString(cfg.KMSBypassFiles, filepath.Join("$HOME", ".aws", "sso", "cache", "token.json")) {
		t.Fatalf("expected aws bypass file, got %#v", cfg.KMSBypassFiles)
	}
}

// TestRunSeal_AWSDefaultsDiscoveryAutoBypass verifies discovery mode auto-
// bypasses ~/.aws/config and ~/.aws/credentials with KMS enabled.
func TestRunSeal_AWSDefaultsDiscoveryAutoBypass(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	_, encoded := mustEncodedSessionKey(t)
	t.Setenv(SessionKeyEnv, encoded)

	svc := newTestService()
	if _, _, err := ensureConfig(); err != nil {
		t.Fatalf("ensure config: %v", err)
	}
	if err := writeConfig(newConfigFixtureBuilder().WithKMSEnabled("alias/lokeys", "us-east-1").Build()); err != nil {
		t.Fatalf("write config: %v", err)
	}

	insecureAWS := filepath.Join(home, defaultDecryptedRel, ".aws", "config")
	if err := os.MkdirAll(filepath.Dir(insecureAWS), dirPerm); err != nil {
		t.Fatalf("mkdir insecure aws dir: %v", err)
	}
	if err := os.WriteFile(insecureAWS, []byte("[default]\nregion=us-east-1\n"), 0600); err != nil {
		t.Fatalf("write insecure aws config: %v", err)
	}
	insecureCreds := filepath.Join(home, defaultDecryptedRel, ".aws", "credentials")
	if err := os.WriteFile(insecureCreds, []byte("[default]\naws_access_key_id=test\n"), 0600); err != nil {
		t.Fatalf("write insecure aws credentials: %v", err)
	}

	if err := svc.RunSeal(); err != nil {
		t.Fatalf("RunSeal failed: %v", err)
	}

	cfg, err := readConfig(filepath.Join(home, configFileRel))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !containsString(cfg.KMSBypassFiles, filepath.Join("$HOME", ".aws", "config")) {
		t.Fatalf("expected discovered config bypass entry, got %#v", cfg.KMSBypassFiles)
	}
	if !containsString(cfg.KMSBypassFiles, filepath.Join("$HOME", ".aws", "credentials")) {
		t.Fatalf("expected discovered credentials bypass entry, got %#v", cfg.KMSBypassFiles)
	}
}

// TestRunSeal_AWSNonDefaultDiscoveryStillNeedsExplicitBypass verifies
// discovered non-default ~/.aws files still require --allow-kms-bypass-file.
func TestRunSeal_AWSNonDefaultDiscoveryStillNeedsExplicitBypass(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	_, encoded := mustEncodedSessionKey(t)
	t.Setenv(SessionKeyEnv, encoded)

	svc := newTestService()
	if _, _, err := ensureConfig(); err != nil {
		t.Fatalf("ensure config: %v", err)
	}
	if err := writeConfig(newConfigFixtureBuilder().WithKMSEnabled("alias/lokeys", "us-east-1").Build()); err != nil {
		t.Fatalf("write config: %v", err)
	}

	insecureAWS := filepath.Join(home, defaultDecryptedRel, ".aws", "sso", "cache", "token.json")
	if err := os.MkdirAll(filepath.Dir(insecureAWS), dirPerm); err != nil {
		t.Fatalf("mkdir insecure aws dir: %v", err)
	}
	if err := os.WriteFile(insecureAWS, []byte("{\"accessToken\":\"test\"}\n"), 0600); err != nil {
		t.Fatalf("write insecure aws token: %v", err)
	}

	err := svc.RunSeal()
	if err == nil {
		t.Fatalf("expected explicit bypass error")
	}
	if !strings.Contains(err.Error(), "without explicit bypass") {
		t.Fatalf("unexpected error: %v", err)
	}

	portable := filepath.Join("$HOME", ".aws", "sso", "cache", "token.json")
	if err := svc.RunSealWithOptions(SealOptions{AllowKMSBypassFiles: []string{portable}}); err != nil {
		t.Fatalf("RunSealWithOptions failed: %v", err)
	}

	cfg, err := readConfig(filepath.Join(home, configFileRel))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !containsString(cfg.KMSBypassFiles, portable) {
		t.Fatalf("expected discovered bypass entry, got %#v", cfg.KMSBypassFiles)
	}
}

// TestRunUnseal_AWSDefaultsDoNotRequireKMSHealthCheck verifies unseal can run
// without AWS/KMS readiness when only auto-bypassed AWS defaults are tracked.
func TestRunUnseal_AWSDefaultsDoNotRequireKMSHealthCheck(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	key, encoded := mustEncodedSessionKey(t)
	t.Setenv(SessionKeyEnv, encoded)

	awsConfigPortable := filepath.Join("$HOME", ".aws", "config")
	awsConfigSecure := filepath.Join(home, defaultEncryptedRel, ".aws", "config")
	if err := os.MkdirAll(filepath.Dir(awsConfigSecure), dirPerm); err != nil {
		t.Fatalf("mkdir secure aws dir: %v", err)
	}
	ciphertext, err := encryptBytes([]byte("[default]\nregion=us-east-1\n"), key)
	if err != nil {
		t.Fatalf("encrypt aws config: %v", err)
	}
	if err := os.WriteFile(awsConfigSecure, ciphertext, 0600); err != nil {
		t.Fatalf("write secure aws config: %v", err)
	}
	if _, _, err := ensureConfig(); err != nil {
		t.Fatalf("ensure config: %v", err)
	}

	if err := writeConfig(newConfigFixtureBuilder().WithManagedFile(awsConfigPortable).WithKMSEnabled("alias/lokeys", "").Build()); err != nil {
		t.Fatalf("write config: %v", err)
	}

	homeAWSDir := filepath.Join(home, ".aws")
	if err := os.MkdirAll(homeAWSDir, dirPerm); err != nil {
		t.Fatalf("mkdir home aws dir: %v", err)
	}

	svc := newTestService()
	if err := svc.RunUnseal(); err != nil {
		t.Fatalf("RunUnseal failed: %v", err)
	}

	if !fileExists(filepath.Join(home, defaultDecryptedRel, ".aws", "config")) {
		t.Fatalf("expected unsealed aws config in insecure dir")
	}
}

// TestRunUnseal_AWSDefaultsDecryptBeforeKMSFailure verifies unseal first
// decrypts local-key AWS defaults, then surfaces KMS failures for remaining
// KMS-protected files with a rerun hint to break the credential dependency loop.
func TestRunUnseal_AWSDefaultsDecryptBeforeKMSFailure(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	key, encoded := mustEncodedSessionKey(t)
	t.Setenv(SessionKeyEnv, encoded)

	awsConfigPortable := filepath.Join("$HOME", ".aws", "config")
	awsConfigSecure := filepath.Join(home, defaultEncryptedRel, ".aws", "config")
	if err := os.MkdirAll(filepath.Dir(awsConfigSecure), dirPerm); err != nil {
		t.Fatalf("mkdir secure aws dir: %v", err)
	}
	awsCiphertext, err := encryptBytes([]byte("[default]\nregion=us-east-1\n"), key)
	if err != nil {
		t.Fatalf("encrypt aws config: %v", err)
	}
	if err := os.WriteFile(awsConfigSecure, awsCiphertext, 0600); err != nil {
		t.Fatalf("write secure aws config: %v", err)
	}
	if _, _, err := ensureConfig(); err != nil {
		t.Fatalf("ensure config: %v", err)
	}

	kmsPortable := filepath.Join("$HOME", "work", "kms-only.txt")
	if err := writeConfig(newConfigFixtureBuilder().WithManagedFiles(awsConfigPortable, kmsPortable).WithKMSEnabled("alias/lokeys", "invalid-region-1").Build()); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if err := os.MkdirAll(filepath.Join(home, ".aws"), dirPerm); err != nil {
		t.Fatalf("mkdir home aws dir: %v", err)
	}

	svc := newTestService()
	err = svc.RunUnseal()
	if err == nil {
		t.Fatalf("expected kms readiness error")
	}
	if !strings.Contains(err.Error(), "run `lokeys unseal` again") {
		t.Fatalf("expected rerun hint, got: %v", err)
	}
	if !fileExists(filepath.Join(home, defaultDecryptedRel, ".aws", "config")) {
		t.Fatalf("expected unsealed aws config in insecure dir")
	}
}

// TestRunUnseal_SkipsPausedFiles verifies paused entries are not extracted,
// while unpaused entries are restored as normal in the same unseal run.
func TestRunUnseal_SkipsPausedFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	key, encoded := mustEncodedSessionKey(t)
	t.Setenv(SessionKeyEnv, encoded)

	pausedPortable := "$HOME/docs/paused.txt"
	unpausedPortable := "$HOME/docs/unpaused.txt"

	pausedSecure := filepath.Join(home, defaultEncryptedRel, "docs", "paused.txt")
	unpausedSecure := filepath.Join(home, defaultEncryptedRel, "docs", "unpaused.txt")
	if err := os.MkdirAll(filepath.Dir(pausedSecure), dirPerm); err != nil {
		t.Fatalf("mkdir secure dir: %v", err)
	}

	pausedCiphertext, err := encryptBytes([]byte("paused-secret\n"), key)
	if err != nil {
		t.Fatalf("encrypt paused file: %v", err)
	}
	if err := os.WriteFile(pausedSecure, pausedCiphertext, 0600); err != nil {
		t.Fatalf("write paused secure file: %v", err)
	}

	unpausedCiphertext, err := encryptBytes([]byte("unpaused-secret\n"), key)
	if err != nil {
		t.Fatalf("encrypt unpaused file: %v", err)
	}
	if err := os.WriteFile(unpausedSecure, unpausedCiphertext, 0600); err != nil {
		t.Fatalf("write unpaused secure file: %v", err)
	}

	pausedHome := filepath.Join(home, "docs", "paused.txt")
	unpausedHome := filepath.Join(home, "docs", "unpaused.txt")
	if err := os.MkdirAll(filepath.Dir(pausedHome), dirPerm); err != nil {
		t.Fatalf("mkdir home dir: %v", err)
	}
	if err := os.WriteFile(pausedHome, []byte("keep-local\n"), 0600); err != nil {
		t.Fatalf("write paused home file: %v", err)
	}
	if err := os.WriteFile(unpausedHome, []byte("replace-me\n"), 0600); err != nil {
		t.Fatalf("write unpaused home file: %v", err)
	}
	if _, _, err := ensureConfig(); err != nil {
		t.Fatalf("ensure config: %v", err)
	}

	if err := writeConfig(newConfigFixtureBuilder().WithManagedFilePaused(pausedPortable, true).WithManagedFilePaused(unpausedPortable, false).Build()); err != nil {
		t.Fatalf("write config: %v", err)
	}

	svc := newTestService()
	if err := svc.RunUnseal(); err != nil {
		t.Fatalf("RunUnseal failed: %v", err)
	}

	pausedInsecure := filepath.Join(home, defaultDecryptedRel, "docs", "paused.txt")
	if fileExists(pausedInsecure) {
		t.Fatalf("expected paused file to remain absent in insecure dir")
	}
	pausedInfo, err := os.Lstat(pausedHome)
	if err != nil {
		t.Fatalf("lstat paused home path: %v", err)
	}
	if pausedInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("expected paused home path to remain regular file")
	}

	unpausedInsecure := filepath.Join(home, defaultDecryptedRel, "docs", "unpaused.txt")
	if !fileExists(unpausedInsecure) {
		t.Fatalf("expected unpaused file in insecure dir")
	}
	unsealedBytes, err := os.ReadFile(unpausedInsecure)
	if err != nil {
		t.Fatalf("read unpaused insecure file: %v", err)
	}
	if string(unsealedBytes) != "unpaused-secret\n" {
		t.Fatalf("unexpected unpaused content: %q", string(unsealedBytes))
	}
	unpausedInfo, err := os.Lstat(unpausedHome)
	if err != nil {
		t.Fatalf("lstat unpaused home path: %v", err)
	}
	if unpausedInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected unpaused home path to be replaced with symlink")
	}
}

// TestRunAddWithPathOverrides_WritesToOverriddenLocations verifies add respects
// explicit config/secure/insecure overrides instead of default home-relative
// directories.
func TestRunAddWithPathOverrides_WritesToOverriddenLocations(t *testing.T) {
	home := t.TempDir()
	configDir := t.TempDir()
	secureDir := t.TempDir()
	insecureDir := t.TempDir()

	t.Setenv("HOME", home)
	t.Setenv(HomeDirEnv, home)
	t.Setenv(ConfigPathEnv, "")
	t.Setenv(SecureDirEnv, "")
	t.Setenv(InsecureDirEnv, "")

	_, encoded := mustEncodedSessionKey(t)
	t.Setenv(SessionKeyEnv, encoded)

	svc := newTestServiceWithOpts(testServiceOpts{paths: PathOverrides{
		Home:        home,
		ConfigPath:  filepath.Join(configDir, "lokeys.json"),
		SecureDir:   secureDir,
		InsecureDir: insecureDir,
	}})

	input := filepath.Join(home, "docs", "secret.txt")
	if err := os.MkdirAll(filepath.Dir(input), dirPerm); err != nil {
		t.Fatalf("mkdir input parent: %v", err)
	}
	if err := os.WriteFile(input, []byte("secret\n"), 0600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	if err := svc.RunAdd(input); err != nil {
		t.Fatalf("RunAdd failed: %v", err)
	}

	if !fileExists(filepath.Join(secureDir, "docs", "secret.txt")) {
		t.Fatalf("expected secure output under overridden secure dir")
	}
	if !fileExists(filepath.Join(configDir, "lokeys.json")) {
		t.Fatalf("expected config under overridden config path")
	}
	if !fileExists(filepath.Join(insecureDir, "docs", "secret.txt")) {
		t.Fatalf("expected insecure output under overridden insecure dir")
	}
}
