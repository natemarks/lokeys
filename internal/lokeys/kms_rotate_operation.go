package lokeys

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// KMSRotateOptions controls CMK re-wrap behavior for existing protected files.
type KMSRotateOptions struct {
	TargetKeyID string
	Region      string
	Profile     string
}

// RunKMSRotate rotates KMS envelope encryption to a target CMK.
func RunKMSRotate(opts KMSRotateOptions) (string, int, error) {
	return defaultService().RunKMSRotate(opts)
}

// RunKMSRotate rotates KMS envelope encryption to a target CMK.
func (s *Service) RunKMSRotate(opts KMSRotateOptions) (string, int, error) {
	cfg, _, err := ensureConfig()
	if err != nil {
		return "", 0, fmt.Errorf("ensure config: %w", err)
	}
	currentKMSCfg, enabled := cfg.kmsRuntimeConfig()
	if !enabled {
		return "", 0, fmt.Errorf("kms rotate requires kms to be enabled in config")
	}
	targetKeyID := strings.TrimSpace(opts.TargetKeyID)
	if targetKeyID == "" {
		return "", 0, fmt.Errorf("target kms key id is required")
	}

	vlogf("kms-rotate start target=%s", targetKeyID)
	oldKey, fromEnv, err := s.deps.Keys.KeyFromSessionEnv()
	if err != nil {
		return "", 0, fmt.Errorf("read session key: %w", err)
	}
	if !fromEnv {
		oldKey, _, err = s.deps.Keys.PromptForKey()
		if err != nil {
			return "", 0, fmt.Errorf("prompt for encryption key: %w", err)
		}
	}
	if err := validateKeyForExistingProtectedFiles(cfg, oldKey); err != nil {
		return "", 0, err
	}
	if err := ensureKMSReady(cfg); err != nil {
		return "", 0, err
	}

	paths, err := s.appPaths()
	if err != nil {
		return "", 0, err
	}
	if err := ensureEncryptedDir(paths.SecureDir); err != nil {
		return "", 0, fmt.Errorf("ensure encrypted dir: %w", err)
	}
	if err := s.deps.Mounter.EnsureMounted(paths.InsecureDir); err != nil {
		return "", 0, fmt.Errorf("ensure ramdisk mounted: %w", err)
	}

	if err := sealTrackedFromRamdisk(cfg, paths, oldKey); err != nil {
		return "", 0, err
	}
	updatedCfg, err := s.sealTrackedAndDiscovered(cfg, paths, oldKey, SealOptions{})
	if err != nil {
		return "", 0, err
	}

	backupPath, err := s.createBackupSnapshot(paths)
	if err != nil {
		return "", 0, err
	}

	targetRegion := strings.TrimSpace(opts.Region)
	if targetRegion == "" {
		targetRegion = currentKMSCfg.Region
	}
	targetProfile := strings.TrimSpace(opts.Profile)
	if targetProfile == "" {
		targetProfile = currentKMSCfg.Profile
	}
	client, resolvedRegion, resolvedProfile, err := newKMSClient(targetRegion, targetProfile)
	if err != nil {
		return backupPath, 0, err
	}
	if err := validateKMSGenerateDataKey(client, targetKeyID, resolvedProfile, resolvedRegion); err != nil {
		return backupPath, 0, err
	}
	targetKMSCfg := kmsRuntimeConfig{
		KeyID:             targetKeyID,
		Region:            resolvedRegion,
		Profile:           resolvedProfile,
		EncryptionContext: updatedCfg.KMS.EncryptionContext,
	}
	plans, skipped, err := buildKMSRotationPlans(updatedCfg, paths, oldKey, currentKMSCfg.Profile, targetKMSCfg)
	if err != nil {
		cleanupRotationTempFiles(plans)
		return backupPath, 0, err
	}
	rotated, err := applyRotationPlans(plans)
	if err != nil {
		cleanupRotationTempFiles(plans)
		return backupPath, rotated, err
	}

	newCfg := &config{ProtectedFiles: append([]string{}, updatedCfg.ProtectedFiles...), KMSBypassFiles: append([]string{}, updatedCfg.KMSBypassFiles...)}
	if updatedCfg.KMS != nil {
		kmsCopy := *updatedCfg.KMS
		newCfg.KMS = &kmsCopy
	} else {
		newCfg.KMS = &kmsConfig{Enabled: true}
	}
	newCfg.KMS.Enabled = true
	newCfg.KMS.KeyID = targetKeyID
	newCfg.KMS.Region = resolvedRegion
	newCfg.KMS.Profile = resolvedProfile
	if strings.HasPrefix(targetKeyID, "alias/") {
		newCfg.KMS.Alias = targetKeyID
	}
	if err := writeConfig(newCfg); err != nil {
		return backupPath, rotated, fmt.Errorf("write config: %w", err)
	}
	vlogf("kms-rotate complete rotated=%d skipped=%d target=%s region=%s", rotated, skipped, targetKeyID, resolvedRegion)
	return backupPath, rotated, nil
}

func buildKMSRotationPlans(cfg *config, paths appPaths, key []byte, sourceProfile string, targetKMSCfg kmsRuntimeConfig) ([]rotationPlan, int, error) {
	plans := make([]rotationPlan, 0, len(cfg.ProtectedFiles))
	skipped := 0
	for _, portable := range cfg.ProtectedFiles {
		if !shouldUseKMSForPortable(cfg, portable) {
			skipped++
			continue
		}
		tracked, err := buildTrackedFileFromPortable(paths.Home, paths.SecureDir, paths.InsecureDir, portable)
		if err != nil {
			return nil, skipped, fmt.Errorf("resolve tracked path %s: %w", portable, err)
		}
		if !fileExists(tracked.SecurePath) {
			if !fileExists(tracked.InsecurePath) {
				return nil, skipped, fmt.Errorf("cannot kms-rotate %s: neither secure nor RAM-disk copy exists", portable)
			}
			if err := ensureParentDir(tracked.SecurePath); err != nil {
				return nil, skipped, fmt.Errorf("ensure secure parent dir: %w", err)
			}
			if err := encryptFile(tracked.InsecurePath, tracked.SecurePath, key, true, targetKMSCfg); err != nil {
				return nil, skipped, fmt.Errorf("encrypt tracked file %s: %w", tracked.InsecurePath, err)
			}
			continue
		}
		ciphertext, err := os.ReadFile(tracked.SecurePath)
		if err != nil {
			return nil, skipped, err
		}
		plaintext, err := decryptBytesWithProfile(ciphertext, key, sourceProfile)
		if err != nil {
			return nil, skipped, fmt.Errorf("kms-rotate %s: %w", portable, err)
		}
		rotatedCiphertext, err := encryptBytesWithOptions(plaintext, key, true, targetKMSCfg, rand.Reader)
		if err != nil {
			return nil, skipped, err
		}
		if err := ensureParentDir(tracked.SecurePath); err != nil {
			return nil, skipped, fmt.Errorf("ensure secure parent dir: %w", err)
		}
		tmpOut, err := os.CreateTemp(filepath.Dir(tracked.SecurePath), filepath.Base(tracked.SecurePath)+".kms-rotate-*.new")
		if err != nil {
			return nil, skipped, err
		}
		tempPath := tmpOut.Name()
		if err := tmpOut.Close(); err != nil {
			_ = os.Remove(tempPath)
			return nil, skipped, err
		}
		if err := os.WriteFile(tempPath, rotatedCiphertext, 0600); err != nil {
			_ = os.Remove(tempPath)
			return nil, skipped, err
		}
		if _, err := decryptBytesWithProfile(rotatedCiphertext, key, targetKMSCfg.Profile); err != nil {
			_ = os.Remove(tempPath)
			return nil, skipped, fmt.Errorf("verify kms-rotated file %s: %w", tracked.SecurePath, err)
		}
		plans = append(plans, rotationPlan{securePath: tracked.SecurePath, tempPath: tempPath})
	}
	return plans, skipped, nil
}
