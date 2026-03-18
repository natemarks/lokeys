package lokeys

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"
)

func keyFromSessionEnv() ([]byte, bool, error) {
	envKey, ok := os.LookupEnv(SessionKeyEnv)
	if !ok || strings.TrimSpace(envKey) == "" {
		return nil, false, nil
	}
	key, err := decodeEncodedKey(strings.TrimSpace(envKey))
	if err != nil {
		return nil, false, fmt.Errorf("%s must contain an encoded 32-byte key: %w", SessionKeyEnv, err)
	}
	return key, true, nil
}

func promptForKeyWithWriter(out io.Writer) ([]byte, string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, "", fmt.Errorf("encryption key required: run in a terminal")
	}
	fmt.Fprint(out, "encryption key (>16 chars): ")
	secret, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(out)
	if err != nil {
		return nil, "", err
	}
	return deriveKeyFromPassphrase(strings.TrimSpace(string(secret)))
}

func promptForNewKeyWithWriter(out io.Writer) ([]byte, string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, "", fmt.Errorf("new encryption key required: run in a terminal")
	}
	fmt.Fprint(out, "new encryption key (>16 chars): ")
	secret, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(out)
	if err != nil {
		return nil, "", err
	}
	fmt.Fprint(out, "confirm new encryption key: ")
	confirm, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(out)
	if err != nil {
		return nil, "", err
	}
	if strings.TrimSpace(string(secret)) != strings.TrimSpace(string(confirm)) {
		return nil, "", fmt.Errorf("new encryption key confirmation does not match")
	}
	return deriveKeyFromPassphrase(strings.TrimSpace(string(secret)))
}

func validateKeyForExistingProtectedFiles(cfg *config, key []byte) error {
	vlogf("validate encryption key against protected files=%d", len(cfg.ProtectedFiles))
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
			if isKMSError(err) {
				return err
			}
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

func keysEqual(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
