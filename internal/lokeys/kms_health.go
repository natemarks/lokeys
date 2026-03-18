package lokeys

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func ensureKMSReady(cfg *config) error {
	kmsCfg, enabled := cfg.kmsRuntimeConfig()
	if !enabled {
		return nil
	}
	vlogf("kms health check key_id=%s region=%s profile=%s", kmsCfg.KeyID, kmsCfg.Region, resolveAWSProfile(kmsCfg.Profile))
	client, _, profile, err := newKMSClient(kmsCfg.Region, kmsCfg.Profile)
	if err != nil {
		return err
	}
	_, err = client.DescribeKey(context.Background(), &kms.DescribeKeyInput{KeyId: &kmsCfg.KeyID})
	if err != nil {
		return wrapKMSError("describe key", profile, kmsCfg.Region, err)
	}
	return nil
}

func anyPortableRequiresKMS(cfg *config, portables []string) bool {
	for _, portable := range portables {
		if shouldUseKMSForPortable(cfg, portable) {
			return true
		}
	}
	return false
}
