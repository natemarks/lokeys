package lokeys

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// EnableKMSOptions controls KMS bootstrap and validation behavior.
type EnableKMSOptions struct {
	Alias   string
	Region  string
	Profile string
	Apply   bool
}

// RunEnableKMS validates or bootstraps AWS KMS envelope settings.
func RunEnableKMS(opts EnableKMSOptions) (string, error) {
	return defaultService().RunEnableKMS(opts)
}

// RunEnableKMS validates or bootstraps AWS KMS envelope settings.
func (s *Service) RunEnableKMS(opts EnableKMSOptions) (string, error) {
	vlogf("enable-kms start alias=%s profile=%s apply=%t", opts.Alias, resolveAWSProfile(opts.Profile), opts.Apply)
	cfg, _, err := s.ensureConfig()
	if err != nil {
		return "", fmt.Errorf("ensure config: %w", err)
	}
	alias := strings.TrimSpace(opts.Alias)
	if alias == "" {
		alias = "alias/lokeys"
	}
	if !strings.HasPrefix(alias, "alias/") {
		return "", fmt.Errorf("kms alias must start with alias/ (example: --alias alias/lokeys)")
	}

	client, resolvedRegion, resolvedProfile, err := newKMSClient(strings.TrimSpace(opts.Region), strings.TrimSpace(opts.Profile))
	if err != nil {
		return "", err
	}
	targetKeyID, err := findAliasTargetKeyID(client, alias, resolvedProfile, resolvedRegion)
	if err != nil {
		return "", err
	}

	action := "validated existing"
	if targetKeyID == "" {
		action = "would create"
		if opts.Apply {
			createResp, err := client.CreateKey(context.Background(), &kms.CreateKeyInput{
				Description: aws.String("lokeys envelope encryption key"),
				KeyUsage:    kmstypes.KeyUsageTypeEncryptDecrypt,
				KeySpec:     kmstypes.KeySpecSymmetricDefault,
			})
			if err != nil {
				return "", wrapKMSError("create key", resolvedProfile, resolvedRegion, err)
			}
			if createResp.KeyMetadata == nil || createResp.KeyMetadata.KeyId == nil {
				return "", fmt.Errorf("%w: create key returned empty key metadata", ErrKMSOperation)
			}
			targetKeyID = *createResp.KeyMetadata.KeyId
			if _, err := client.EnableKeyRotation(context.Background(), &kms.EnableKeyRotationInput{KeyId: &targetKeyID}); err != nil {
				return "", wrapKMSError("enable key rotation", resolvedProfile, resolvedRegion, err)
			}
			if _, err := client.CreateAlias(context.Background(), &kms.CreateAliasInput{AliasName: &alias, TargetKeyId: &targetKeyID}); err != nil {
				return "", wrapKMSError("create alias", resolvedProfile, resolvedRegion, err)
			}
			action = "created"
		}
	}

	if opts.Apply {
		if err := validateKMSGenerateDataKey(client, alias, resolvedProfile, resolvedRegion); err != nil {
			return "", err
		}
		updated := &config{ProtectedFiles: cfg.protectedFileEntries(), KMSBypassFiles: append([]string{}, cfg.KMSBypassFiles...)}
		updated.KMS = &kmsConfig{
			Enabled:           true,
			KeyID:             alias,
			Region:            resolvedRegion,
			Profile:           resolvedProfile,
			Alias:             alias,
			EncryptionContext: map[string]string{"app": "lokeys"},
		}
		if err := s.writeConfig(updated); err != nil {
			return "", fmt.Errorf("write config: %w", err)
		}
		message := fmt.Sprintf("KMS %s key alias %s in region %s and updated config", action, alias, resolvedRegion)
		vlogf("enable-kms complete apply message=%s", message)
		return message, nil
	}

	if targetKeyID == "" {
		message := fmt.Sprintf("Dry run: %s CMK with alias %s in region %s; rerun with --apply to proceed", action, alias, resolvedRegion)
		vlogf("enable-kms complete dry-run message=%s", message)
		return message, nil
	}
	if err := validateKMSGenerateDataKey(client, alias, resolvedProfile, resolvedRegion); err != nil {
		return "", err
	}
	message := fmt.Sprintf("Dry run: validated KMS alias %s in region %s; rerun with --apply to write config", alias, resolvedRegion)
	vlogf("enable-kms complete dry-run message=%s", message)
	return message, nil
}

func findAliasTargetKeyID(client kmsAPI, alias string, profile string, region string) (string, error) {
	var marker *string
	for {
		resp, err := client.ListAliases(context.Background(), &kms.ListAliasesInput{Marker: marker, Limit: aws.Int32(100)})
		if err != nil {
			return "", wrapKMSError("list aliases", profile, region, err)
		}
		for _, a := range resp.Aliases {
			if a.AliasName == nil || *a.AliasName != alias {
				continue
			}
			if a.TargetKeyId == nil {
				return "", nil
			}
			return *a.TargetKeyId, nil
		}
		if !resp.Truncated || resp.NextMarker == nil {
			break
		}
		marker = resp.NextMarker
	}
	return "", nil
}

func validateKMSGenerateDataKey(client kmsAPI, keyID string, profile string, region string) error {
	if _, err := client.DescribeKey(context.Background(), &kms.DescribeKeyInput{KeyId: &keyID}); err != nil {
		return wrapKMSError("describe key", profile, region, err)
	}
	resp, err := client.GenerateDataKey(context.Background(), &kms.GenerateDataKeyInput{KeyId: &keyID, KeySpec: kmstypes.DataKeySpecAes256, EncryptionContext: map[string]string{"app": "lokeys"}})
	if err != nil {
		return wrapKMSError("generate data key", profile, region, err)
	}
	zeroBytes(resp.Plaintext)
	if len(resp.CiphertextBlob) == 0 {
		return fmt.Errorf("%w: empty ciphertext blob from GenerateDataKey", ErrKMSOperation)
	}
	return nil
}
