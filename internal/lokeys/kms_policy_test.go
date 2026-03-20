package lokeys

import (
	"path/filepath"
	"testing"
)

func TestShouldUseKMSForPortable_AWSDefaultsAutoBypass(t *testing.T) {
	cfg := &config{KMS: &kmsConfig{Enabled: true, KeyID: "alias/lokeys", Region: "us-east-1"}}

	awsConfig := filepath.Join("$HOME", ".aws", "config")
	awsCredentials := filepath.Join("$HOME", ".aws", "credentials")
	for _, portable := range []string{awsConfig, awsCredentials} {
		if shouldUseKMSForPortable(cfg, portable) {
			t.Fatalf("expected aws default path to bypass kms: %s", portable)
		}
	}
}

func TestShouldUseKMSForPortable_NonDefaultAWSPathStillRequiresBypass(t *testing.T) {
	cfg := &config{KMS: &kmsConfig{Enabled: true, KeyID: "alias/lokeys", Region: "us-east-1"}}
	portable := filepath.Join("$HOME", ".aws", "sso", "cache", "token.json")

	if !shouldUseKMSForPortable(cfg, portable) {
		t.Fatalf("expected non-default aws path to still require kms by default")
	}
}
