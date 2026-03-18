package lokeys

import (
	"context"
	"errors"
	"fmt"

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

func newKMSClient(region string) (kmsAPI, string, error) {
	ctx := context.Background()
	var cfg aws.Config
	var err error
	if region != "" {
		cfg, err = loadAWSConfig(ctx, awsconfig.WithRegion(region))
	} else {
		cfg, err = loadAWSConfig(ctx)
	}
	if err != nil {
		return nil, "", fmt.Errorf("%w: load aws config: %v", ErrKMSOperation, err)
	}
	resolvedRegion := cfg.Region
	if resolvedRegion == "" {
		return nil, "", fmt.Errorf("%w: aws region is not configured", ErrKMSOperation)
	}
	client := kms.NewFromConfig(cfg)
	return client, resolvedRegion, nil
}

func wrapKMSError(action string, err error) error {
	if err == nil {
		return nil
	}
	var notFound *types.NotFoundException
	if errors.As(err, &notFound) {
		return fmt.Errorf("%w: %s: %s", ErrKMSOperation, action, notFound.ErrorMessage())
	}
	return fmt.Errorf("%w: %s: %v", ErrKMSOperation, action, err)
}
