package lokeys

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

type rotationPlan struct {
	securePath string
	tempPath   string
}

func sealTrackedFromRamdisk(cfg *config, paths appPaths, key []byte) error {
	for _, portable := range cfg.ProtectedFiles {
		tracked, err := buildTrackedFileFromPortable(paths.Home, paths.SecureDir, paths.InsecureDir, portable)
		if err != nil {
			return fmt.Errorf("resolve tracked path %s: %w", portable, err)
		}

		if !fileExists(tracked.InsecurePath) {
			continue
		}
		if err := ensureParentDir(tracked.SecurePath); err != nil {
			return fmt.Errorf("ensure secure parent dir: %w", err)
		}
		useKMS := shouldUseKMSForPortable(cfg, tracked.Portable)
		kmsCfg, _ := cfg.kmsRuntimeConfig()
		if err := encryptFile(tracked.InsecurePath, tracked.SecurePath, key, useKMS, kmsCfg); err != nil {
			return fmt.Errorf("encrypt tracked file %s: %w", tracked.InsecurePath, err)
		}
	}
	return nil
}

func buildRotationPlans(cfg *config, paths appPaths, oldKey []byte, newKey []byte) ([]rotationPlan, error) {
	plans := make([]rotationPlan, 0, len(cfg.ProtectedFiles))
	for _, portable := range cfg.ProtectedFiles {
		tracked, err := buildTrackedFileFromPortable(paths.Home, paths.SecureDir, paths.InsecureDir, portable)
		if err != nil {
			return nil, fmt.Errorf("resolve tracked path %s: %w", portable, err)
		}

		if !fileExists(tracked.SecurePath) && !fileExists(tracked.InsecurePath) {
			return nil, fmt.Errorf("cannot rotate %s: neither secure nor RAM-disk copy exists", portable)
		}

		if err := ensureParentDir(tracked.SecurePath); err != nil {
			return nil, fmt.Errorf("ensure secure parent dir: %w", err)
		}
		tmpOut, err := os.CreateTemp(filepath.Dir(tracked.SecurePath), filepath.Base(tracked.SecurePath)+".rotate-*.new")
		if err != nil {
			return nil, err
		}
		tempPath := tmpOut.Name()
		if err := tmpOut.Close(); err != nil {
			_ = os.Remove(tempPath)
			return nil, err
		}

		plaintext, err := plaintextForRotation(tracked.InsecurePath, tracked.SecurePath, oldKey)
		if err != nil {
			_ = os.Remove(tempPath)
			return nil, fmt.Errorf("rotate %s: %w", portable, err)
		}

		useKMS := shouldUseKMSForPortable(cfg, tracked.Portable)
		kmsCfg, _ := cfg.kmsRuntimeConfig()
		ciphertext, err := encryptBytesWithOptions(plaintext, newKey, useKMS, kmsCfg, rand.Reader)
		if err != nil {
			_ = os.Remove(tempPath)
			return nil, err
		}
		if err := os.WriteFile(tempPath, ciphertext, 0600); err != nil {
			_ = os.Remove(tempPath)
			return nil, err
		}
		if err := verifyRotatedTempFile(tempPath, plaintext, newKey); err != nil {
			_ = os.Remove(tempPath)
			return nil, err
		}

		plans = append(plans, rotationPlan{securePath: tracked.SecurePath, tempPath: tempPath})
	}
	return plans, nil
}

func plaintextForRotation(insecurePath string, securePath string, oldKey []byte) ([]byte, error) {
	if fileExists(insecurePath) {
		return os.ReadFile(insecurePath)
	}
	if !fileExists(securePath) {
		return nil, fmt.Errorf("missing secure file: %s", securePath)
	}
	ciphertext, err := os.ReadFile(securePath)
	if err != nil {
		return nil, err
	}
	plaintext, err := decryptBytes(ciphertext, oldKey)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func verifyRotatedTempFile(tempPath string, expectedPlaintext []byte, newKey []byte) error {
	tmpCiphertext, err := os.ReadFile(tempPath)
	if err != nil {
		return err
	}
	decrypted, err := decryptBytes(tmpCiphertext, newKey)
	if err != nil {
		return err
	}
	if !keysEqual(decrypted, expectedPlaintext) {
		return fmt.Errorf("verification failed for rotated file %s", tempPath)
	}
	return nil
}

func applyRotationPlans(plans []rotationPlan) (int, error) {
	for i, plan := range plans {
		if err := os.Rename(plan.tempPath, plan.securePath); err != nil {
			return i, err
		}
	}
	return len(plans), nil
}

func cleanupRotationTempFiles(plans []rotationPlan) {
	for _, plan := range plans {
		if plan.tempPath == "" {
			continue
		}
		_ = os.Remove(plan.tempPath)
	}
}
