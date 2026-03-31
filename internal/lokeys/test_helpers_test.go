package lokeys

import (
	"io"
	"os"
	"testing"
)

// testServiceOpts configures dependency overrides used by helper constructors.
type testServiceOpts struct {
	newKeyPrompt []byte
	oldKeyPrompt []byte
	paths        PathOverrides
}

type testMounter struct{}

func (testMounter) EnsureMounted(path string) error {
	return os.MkdirAll(path, dirPerm)
}

type testKeySource struct {
	newKeyPrompt []byte
	oldKeyPrompt []byte
}

func (k testKeySource) KeyForCommand() ([]byte, error) {
	if key, ok, err := keyFromSessionEnv(); err != nil {
		return nil, err
	} else if ok {
		return key, nil
	}
	if k.oldKeyPrompt != nil {
		copied := make([]byte, len(k.oldKeyPrompt))
		copy(copied, k.oldKeyPrompt)
		return copied, nil
	}
	key, _, err := deriveKeyFromPassphrase("this is a sufficiently long passphrase")
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (k testKeySource) KeyFromSessionEnv() ([]byte, bool, error) {
	return keyFromSessionEnv()
}

func (k testKeySource) PromptForKey() ([]byte, string, error) {
	if k.oldKeyPrompt == nil {
		return deriveKeyFromPassphrase("this is a sufficiently long prompted passphrase")
	}
	copied := make([]byte, len(k.oldKeyPrompt))
	copy(copied, k.oldKeyPrompt)
	return copied, "", nil
}

func (k testKeySource) PromptForNewKey() ([]byte, string, error) {
	if k.newKeyPrompt == nil {
		return deriveKeyFromPassphrase("this is a sufficiently long new prompted passphrase")
	}
	copied := make([]byte, len(k.newKeyPrompt))
	copy(copied, k.newKeyPrompt)
	return copied, "", nil
}

// mustEncodedSessionKey derives a stable test key and encoded env value used by
// command tests so they can bypass interactive key prompts.
func mustEncodedSessionKey(t *testing.T) ([]byte, string) {
	t.Helper()
	key, encoded, err := deriveKeyFromPassphrase("this is a sufficiently long passphrase")
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	return key, encoded
}

// newTestService returns a service configured for deterministic tests where
// mount behavior is stubbed and command output is discarded.
func newTestService() *Service {
	return newTestServiceWithOpts(testServiceOpts{})
}

// newTestServiceWithOpts builds a test service with optional prompt overrides
// for rotate/session-key focused tests.
func newTestServiceWithOpts(opts testServiceOpts) *Service {
	deps := Deps{
		Stdout:  io.Discard,
		Stderr:  io.Discard,
		Mounter: testMounter{},
		Paths:   opts.paths,
		Keys: testKeySource{
			newKeyPrompt: opts.newKeyPrompt,
			oldKeyPrompt: opts.oldKeyPrompt,
		},
	}

	return NewService(deps)
}

func protectedFilesFromPaths(paths []string) []protectedFile {
	entries := make([]protectedFile, 0, len(paths))
	for _, path := range paths {
		entries = append(entries, protectedFile{Path: path})
	}
	return entries
}

// configFixtureBuilder creates test configs with concise, readable setup.
//
// It is intentionally test-only and optimized for common cases:
// managed files (paused/unpaused), KMS enabled/disabled, and bypass entries.
type configFixtureBuilder struct {
	cfg config
}

func newConfigFixtureBuilder() *configFixtureBuilder {
	return &configFixtureBuilder{
		cfg: config{ProtectedFiles: []protectedFile{}},
	}
}

func (b *configFixtureBuilder) WithManagedFiles(paths ...string) *configFixtureBuilder {
	for _, path := range paths {
		b.cfg.ProtectedFiles = append(b.cfg.ProtectedFiles, protectedFile{Path: path, Paused: false})
	}
	return b
}

func (b *configFixtureBuilder) WithManagedFile(path string) *configFixtureBuilder {
	return b.WithManagedFilePaused(path, false)
}

func (b *configFixtureBuilder) WithManagedFilePaused(path string, paused bool) *configFixtureBuilder {
	b.cfg.ProtectedFiles = append(b.cfg.ProtectedFiles, protectedFile{Path: path, Paused: paused})
	return b
}

func (b *configFixtureBuilder) WithKMSEnabled(keyID string, region string) *configFixtureBuilder {
	b.cfg.KMS = &kmsConfig{Enabled: true, KeyID: keyID, Region: region}
	return b
}

func (b *configFixtureBuilder) WithKMSDisabled() *configFixtureBuilder {
	b.cfg.KMS = &kmsConfig{Enabled: false}
	return b
}

func (b *configFixtureBuilder) WithKMSBypassFiles(paths ...string) *configFixtureBuilder {
	b.cfg.KMSBypassFiles = append(b.cfg.KMSBypassFiles, paths...)
	return b
}

func (b *configFixtureBuilder) Build() *config {
	result := &config{
		ProtectedFiles: cloneProtectedFiles(b.cfg.ProtectedFiles),
		KMSBypassFiles: append([]string{}, b.cfg.KMSBypassFiles...),
	}
	if b.cfg.KMS != nil {
		kmsCopy := *b.cfg.KMS
		if kmsCopy.EncryptionContext != nil {
			kmsCopy.EncryptionContext = make(map[string]string, len(kmsCopy.EncryptionContext))
			for key, value := range kmsCopy.EncryptionContext {
				kmsCopy.EncryptionContext[key] = value
			}
		}
		result.KMS = &kmsCopy
	}
	return result
}

func containsString(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}
