package lokeys

import "io"

// RamdiskMounter defines mount behavior for RAM-disk setup.
type RamdiskMounter interface {
	EnsureMounted(path string) error
}

// KeySource defines key retrieval and prompting boundaries.
type KeySource interface {
	KeyForCommand() ([]byte, error)
	KeyFromSessionEnv() ([]byte, bool, error)
	PromptForKey() ([]byte, string, error)
	PromptForNewKey() ([]byte, string, error)
}

type defaultRamdiskMounter struct{}

func (defaultRamdiskMounter) EnsureMounted(path string) error {
	return ensureRamdiskMounted(path)
}

type defaultKeySource struct {
	stderr io.Writer
}

func (k defaultKeySource) KeyForCommand() ([]byte, error) {
	if key, ok, err := keyFromSessionEnv(); err != nil {
		return nil, err
	} else if ok {
		return key, nil
	}
	key, _, err := promptForKeyWithWriter(k.stderr)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (k defaultKeySource) KeyFromSessionEnv() ([]byte, bool, error) {
	return keyFromSessionEnv()
}

func (k defaultKeySource) PromptForKey() ([]byte, string, error) {
	return promptForKeyWithWriter(k.stderr)
}

func (k defaultKeySource) PromptForNewKey() ([]byte, string, error) {
	return promptForNewKeyWithWriter(k.stderr)
}
