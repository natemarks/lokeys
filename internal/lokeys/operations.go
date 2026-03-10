package lokeys

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
)

// RunList lists tracked files and their secure/insecure status.
func RunList(session bool) error {
	config, created, err := ensureConfig()
	if err != nil {
		return err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	configPath := filepath.Join(home, configFileRel)
	secureDir := filepath.Join(home, defaultEncryptedRel)
	insecureDir := filepath.Join(home, defaultDecryptedRel)

	if created {
		fmt.Printf("No protected files found. Creating config at %s, encrypted storage at %s, and mounting a 100MB RAM disk at %s.\n", configPath, secureDir, insecureDir)
		if err := ensureEncryptedDir(secureDir); err != nil {
			return err
		}
		if err := ensureRamdiskMounted(insecureDir); err != nil {
			return err
		}
		return nil
	}

	if err := ensureEncryptedDir(secureDir); err != nil {
		return err
	}

	if len(config.ProtectedFiles) == 0 {
		fmt.Println("No protected files found.")
		return nil
	}

	needsKey := false
	for _, portable := range config.ProtectedFiles {
		fullPath, err := expandPortablePath(portable)
		if err != nil {
			return err
		}
		rel, err := relToHome(fullPath)
		if err != nil {
			return err
		}
		if fileExists(filepath.Join(secureDir, rel)) {
			needsKey = true
			break
		}
	}

	var key []byte
	if needsKey {
		key, err = keyForCommand(session)
		if err != nil {
			return err
		}
		if err := validateKeyForExistingProtectedFiles(config, key); err != nil {
			return err
		}
	}

	if err := ensureRamdiskMounted(insecureDir); err != nil {
		return err
	}

	for _, portable := range config.ProtectedFiles {
		fullPath, err := expandPortablePath(portable)
		if err != nil {
			return err
		}
		rel, err := relToHome(fullPath)
		if err != nil {
			return err
		}
		insecurePath := filepath.Join(insecureDir, rel)
		securePath := filepath.Join(secureDir, rel)

		var insecureHash, secureHash string
		insecureExists := fileExists(insecurePath)
		secureExists := fileExists(securePath)

		if insecureExists {
			insecureHash, err = sha256File(insecurePath)
			if err != nil {
				return err
			}
		}

		if secureExists && key != nil {
			ciphertext, err := os.ReadFile(securePath)
			if err != nil {
				return err
			}
			plaintext, err := decryptBytes(ciphertext, key)
			if err != nil {
				return err
			}
			secureHash = fmt.Sprintf("%x", sha256.Sum256(plaintext))
		}

		status := "OK"
		if !insecureExists {
			status = "MISSING_INSECURE"
		} else if !secureExists {
			status = "MISSING_SECURE"
		} else if insecureHash != secureHash {
			status = "MISMATCH"
		}

		fmt.Printf("%s  insecure=%s  secure=%s  %s\n", portable, hashOrMissing(insecureHash), hashOrMissing(secureHash), status)
	}

	return nil
}

// RunAdd adds a file to protection and replaces it with a RAM-disk symlink.
func RunAdd(pathArg string, session bool) error {
	fullPath, err := expandUserPath(pathArg)
	if err != nil {
		return err
	}

	config, _, err := ensureConfig()
	if err != nil {
		return err
	}
	key, err := keyForCommand(session)
	if err != nil {
		return err
	}
	if err := validateKeyForExistingProtectedFiles(config, key); err != nil {
		return err
	}

	portable, err := portablePath(fullPath)
	if err != nil {
		return err
	}

	if containsString(config.ProtectedFiles, portable) {
		fmt.Printf("%s already protected.\n", portable)
		return nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	secureDir := filepath.Join(home, defaultEncryptedRel)
	insecureDir := filepath.Join(home, defaultDecryptedRel)

	if err := ensureEncryptedDir(secureDir); err != nil {
		return err
	}
	if err := ensureRamdiskMounted(insecureDir); err != nil {
		return err
	}

	if err := ensureRegularFile(fullPath); err != nil {
		return err
	}

	rel, err := relToHome(fullPath)
	if err != nil {
		return err
	}

	securePath := filepath.Join(secureDir, rel)
	insecurePath := filepath.Join(insecureDir, rel)

	if err := ensureParentDir(insecurePath); err != nil {
		return err
	}
	if err := ensureParentDir(securePath); err != nil {
		return err
	}

	if err := copyFile(fullPath, insecurePath, 0600); err != nil {
		return err
	}
	if err := encryptFile(insecurePath, securePath, key); err != nil {
		return err
	}

	if err := replaceWithSymlink(fullPath, insecurePath); err != nil {
		return err
	}

	config.ProtectedFiles = append(config.ProtectedFiles, portable)
	return writeConfig(config)
}

// RunSeal encrypts all tracked RAM-disk files into secure storage.
func RunSeal(session bool) error {
	config, _, err := ensureConfig()
	if err != nil {
		return err
	}
	key, err := keyForCommand(session)
	if err != nil {
		return err
	}
	if err := validateKeyForExistingProtectedFiles(config, key); err != nil {
		return err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	secureDir := filepath.Join(home, defaultEncryptedRel)
	insecureDir := filepath.Join(home, defaultDecryptedRel)

	if err := ensureEncryptedDir(secureDir); err != nil {
		return err
	}
	if err := ensureRamdiskMounted(insecureDir); err != nil {
		return err
	}

	for _, portable := range config.ProtectedFiles {
		fullPath, err := expandPortablePath(portable)
		if err != nil {
			return err
		}
		rel, err := relToHome(fullPath)
		if err != nil {
			return err
		}
		insecurePath := filepath.Join(insecureDir, rel)
		securePath := filepath.Join(secureDir, rel)

		if err := ensureParentDir(securePath); err != nil {
			return err
		}
		if err := encryptFile(insecurePath, securePath, key); err != nil {
			return err
		}
	}

	return nil
}

// RunUnseal decrypts all tracked files into RAM-disk storage.
func RunUnseal(session bool) error {
	config, _, err := ensureConfig()
	if err != nil {
		return err
	}
	key, err := keyForCommand(session)
	if err != nil {
		return err
	}
	if err := validateKeyForExistingProtectedFiles(config, key); err != nil {
		return err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	secureDir := filepath.Join(home, defaultEncryptedRel)
	insecureDir := filepath.Join(home, defaultDecryptedRel)

	if err := ensureEncryptedDir(secureDir); err != nil {
		return err
	}
	if err := ensureRamdiskMounted(insecureDir); err != nil {
		return err
	}

	for _, portable := range config.ProtectedFiles {
		fullPath, err := expandPortablePath(portable)
		if err != nil {
			return err
		}
		rel, err := relToHome(fullPath)
		if err != nil {
			return err
		}
		insecurePath := filepath.Join(insecureDir, rel)
		securePath := filepath.Join(secureDir, rel)

		if err := ensureParentDir(insecurePath); err != nil {
			return err
		}
		if err := decryptFile(securePath, insecurePath, key); err != nil {
			return err
		}
		if err := replaceWithSymlink(fullPath, insecurePath); err != nil {
			return err
		}
	}

	return nil
}

// RunBackup creates a timestamped tar backup in secure storage.
func RunBackup() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if _, _, err := ensureConfig(); err != nil {
		return "", err
	}
	secureDir := filepath.Join(home, defaultEncryptedRel)
	configPath := filepath.Join(home, configFileRel)
	return createBackupTar(secureDir, configPath)
}

// RunSessionExport prompts for a key and returns an export command line.
func RunSessionExport() (string, error) {
	_, encoded, err := promptForKey()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("export %s='%s'", SessionKeyEnv, encoded), nil
}

func sha256File(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum), nil
}
