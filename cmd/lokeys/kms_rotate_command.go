package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/google/subcommands"
	"lokeys/internal/lokeys"
)

type kmsRotateCommand struct {
	targetKeyID string
	region      string
	profile     string
}

func (*kmsRotateCommand) Name() string     { return "kms-rotate" }
func (*kmsRotateCommand) Synopsis() string { return "rotate KMS envelope to a target CMK" }
func (*kmsRotateCommand) Usage() string {
	return "kms-rotate --target-key-id <alias-or-arn> [--region us-east-1] [--profile default]\n\tRe-wrap KMS-managed protected files with a target KMS key.\n"
}

func (c *kmsRotateCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.targetKeyID, "target-key-id", "", "target KMS key identifier (alias or arn)")
	fs.StringVar(&c.region, "region", "", "target KMS region (defaults to configured region)")
	fs.StringVar(&c.profile, "profile", "", "AWS shared config profile for KMS access")
}

func (c *kmsRotateCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	return runWithExitStatus(runKMSRotate(f.Args(), c.targetKeyID, c.region, c.profile))
}

func runKMSRotate(args []string, targetKeyID string, region string, profile string) error {
	if err := requireNoArgs(args, "kms-rotate"); err != nil {
		return err
	}
	if targetKeyID == "" {
		return usageError("kms-rotate requires --target-key-id (example: --target-key-id alias/lokeys-next)")
	}
	backupPath, rotated, err := lokeys.RunKMSRotate(lokeys.KMSRotateOptions{TargetKeyID: targetKeyID, Region: region, Profile: profile})
	if err != nil {
		return err
	}
	fmt.Printf("backup created: %s\n", backupPath)
	fmt.Printf("kms-rotated encrypted files: %d\n", rotated)
	return nil
}
