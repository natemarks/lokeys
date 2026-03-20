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
