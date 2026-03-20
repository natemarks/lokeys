package lokeys

import (
	"path/filepath"
	"strings"
)

type kmsRuntimeConfig struct {
	KeyID             string
	Region            string
	Profile           string
	EncryptionContext map[string]string
}

func (c *config) kmsRuntimeConfig() (kmsRuntimeConfig, bool) {
	if c == nil || c.KMS == nil {
		return kmsRuntimeConfig{}, false
	}
	if !c.KMS.Enabled || strings.TrimSpace(c.KMS.KeyID) == "" {
		return kmsRuntimeConfig{}, false
	}
	ctxCopy := map[string]string{}
	for k, v := range c.KMS.EncryptionContext {
		ctxCopy[k] = v
	}
	return kmsRuntimeConfig{
		KeyID:             strings.TrimSpace(c.KMS.KeyID),
		Region:            strings.TrimSpace(c.KMS.Region),
		Profile:           strings.TrimSpace(c.KMS.Profile),
		EncryptionContext: ctxCopy,
	}, true
}

func (c *config) isKMSBypassedPortable(portable string) bool {
	if c == nil {
		return false
	}
	for _, p := range c.KMSBypassFiles {
		if p == portable {
			return true
		}
	}
	return false
}

func shouldUseKMSForPortable(cfg *config, portable string) bool {
	_, enabled := cfg.kmsRuntimeConfig()
	if !enabled {
		return false
	}
	if isAWSAutoBypassPortable(portable) {
		return false
	}
	return !cfg.isKMSBypassedPortable(portable)
}

func isAWSAutoBypassPortable(portable string) bool {
	configPortable := filepath.Join("$HOME", ".aws", "config")
	credentialsPortable := filepath.Join("$HOME", ".aws", "credentials")
	return portable == configPortable || portable == credentialsPortable
}

func isAWSCredentialPortablePath(portable string) bool {
	if portable == "$HOME/.aws" {
		return true
	}
	prefix := "$HOME" + string(filepath.Separator) + ".aws" + string(filepath.Separator)
	return strings.HasPrefix(portable, prefix)
}

func appendUnique(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}
