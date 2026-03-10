package lokeys

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"
)

func keyForCommand(session bool) ([]byte, error) {
	if session {
		if envKey, ok := os.LookupEnv(SessionKeyEnv); ok && strings.TrimSpace(envKey) != "" {
			key, err := decodeEncodedKey(strings.TrimSpace(envKey))
			if err != nil {
				return nil, fmt.Errorf("%s must contain an encoded 32-byte key: %w", SessionKeyEnv, err)
			}
			return key, nil
		}
	}

	key, encoded, err := promptForKey()
	if err != nil {
		return nil, err
	}

	if session {
		if err := os.Setenv(SessionKeyEnv, encoded); err != nil {
			return nil, fmt.Errorf("set %s: %w", SessionKeyEnv, err)
		}
		fmt.Fprintf(os.Stderr, "session key loaded for this run; export %s in your shell to reuse across commands\n", SessionKeyEnv)
	}

	return key, nil
}

func promptForKey() ([]byte, string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, "", fmt.Errorf("encryption key required: run in a terminal")
	}
	fmt.Fprint(os.Stderr, "encryption key (>16 chars): ")
	secret, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, "", err
	}
	return deriveKeyFromPassphrase(strings.TrimSpace(string(secret)))
}

func validateKeyForExistingProtectedFiles(cfg *config, key []byte) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	secureDir := filepath.Join(home, defaultEncryptedRel)

	for _, portable := range cfg.ProtectedFiles {
		fullPath, err := expandPortablePath(portable)
		if err != nil {
			return err
		}
		rel, err := relToHome(fullPath)
		if err != nil {
			return err
		}
		securePath := filepath.Join(secureDir, rel)
		if !fileExists(securePath) {
			continue
		}
		ciphertext, err := os.ReadFile(securePath)
		if err != nil {
			return err
		}
		if _, err := decryptBytes(ciphertext, key); err != nil {
			return fmt.Errorf("invalid encryption key for protected files")
		}
		return nil
	}

	return nil
}

func decodeEncodedKey(raw string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid encoded session key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid encoded session key length: got %d bytes, want 32", len(key))
	}
	return key, nil
}

func deriveKeyFromPassphrase(raw string) ([]byte, string, error) {
	if len(raw) <= 16 {
		return nil, "", fmt.Errorf("encryption key must be more than 16 characters")
	}
	sum := sha256.Sum256([]byte(raw))
	key := make([]byte, len(sum))
	copy(key, sum[:])
	encoded := base64.StdEncoding.EncodeToString(key)
	return key, encoded, nil
}
