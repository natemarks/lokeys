package lokeys

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// ErrKMSOperation marks failures from AWS KMS calls or KMS configuration checks.
var ErrKMSOperation = errors.New("kms operation failed")

type kmsAPI interface {
	GenerateDataKey(ctx context.Context, params *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
	DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	CreateKey(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error)
	EnableKeyRotation(ctx context.Context, params *kms.EnableKeyRotationInput, optFns ...func(*kms.Options)) (*kms.EnableKeyRotationOutput, error)
	CreateAlias(ctx context.Context, params *kms.CreateAliasInput, optFns ...func(*kms.Options)) (*kms.CreateAliasOutput, error)
	ListAliases(ctx context.Context, params *kms.ListAliasesInput, optFns ...func(*kms.Options)) (*kms.ListAliasesOutput, error)
}

var loadAWSConfig = awsconfig.LoadDefaultConfig

func newKMSClient(region string, profile string) (kmsAPI, string, string, error) {
	resolvedProfile := resolveAWSProfile(profile)
	vlogf("create kms client requested_region=%s profile=%s", region, resolvedProfile)
	ctx := context.Background()
	var cfg aws.Config
	var err error
	opts := []func(*awsconfig.LoadOptions) error{}
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	if strings.TrimSpace(profile) != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(strings.TrimSpace(profile)))
	}
	cfg, err = loadAWSConfig(ctx, opts...)
	if err != nil {
		return nil, "", "", fmt.Errorf("%w: load aws config for profile %q region %q: %v", ErrKMSOperation, resolvedProfile, strings.TrimSpace(region), err)
	}
	resolvedRegion := cfg.Region
	if resolvedRegion == "" {
		return nil, "", "", fmt.Errorf("%w: aws region is not configured for profile %q", ErrKMSOperation, resolvedProfile)
	}
	vlogf("created kms client resolved_region=%s profile=%s", resolvedRegion, resolvedProfile)
	client := kms.NewFromConfig(cfg)
	return client, resolvedRegion, resolvedProfile, nil
}

func wrapKMSError(action string, profile string, region string, err error) error {
	if err == nil {
		return nil
	}
	resolvedProfile := resolveAWSProfile(profile)
	resolvedRegion := strings.TrimSpace(region)
	if resolvedRegion == "" {
		resolvedRegion = "(unspecified)"
	}
	vlogf("kms access error profile=%s region=%s action=%s err=%v", resolvedProfile, resolvedRegion, action, err)
	var notFound *types.NotFoundException
	if errors.As(err, &notFound) {
		return fmt.Errorf("%w: profile %q region %q %s: %s", ErrKMSOperation, resolvedProfile, resolvedRegion, action, notFound.ErrorMessage())
	}
	return fmt.Errorf("%w: profile %q region %q %s: %v", ErrKMSOperation, resolvedProfile, resolvedRegion, action, err)
}

func resolveAWSProfile(profile string) string {
	trimmed := strings.TrimSpace(profile)
	if trimmed != "" {
		return trimmed
	}
	envProfile := strings.TrimSpace(os.Getenv("AWS_PROFILE"))
	if envProfile != "" {
		return envProfile
	}
	return "default"
}
