package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/google/subcommands"
	"lokeys/internal/lokeys"
)

type enableKMSCommand struct {
	alias   string
	region  string
	profile string
	apply   bool
}

func (*enableKMSCommand) Name() string { return "enable-kms" }
func (*enableKMSCommand) Synopsis() string {
	return "validate or bootstrap AWS KMS envelope encryption"
}
func (*enableKMSCommand) Usage() string {
	return "enable-kms [--alias alias/lokeys] [--region us-east-1] [--profile default] [--apply]\n\tValidate KMS CMK setup; add --apply to create alias/key and update config.\n"
}

func (c *enableKMSCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.alias, "alias", "alias/lokeys", "KMS alias to use or create")
	fs.StringVar(&c.region, "region", "", "AWS region (default from AWS SDK config chain)")
	fs.StringVar(&c.profile, "profile", "", "AWS shared config profile for KMS access")
	fs.BoolVar(&c.apply, "apply", false, "perform changes (default is dry run)")
}

func (c *enableKMSCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	return runWithExitStatus(runEnableKMS(f.Args(), c.alias, c.region, c.profile, c.apply))
}

func runEnableKMS(args []string, alias string, region string, profile string, apply bool) error {
	if err := requireNoArgs(args, "enable-kms"); err != nil {
		return err
	}
	message, err := lokeys.RunEnableKMS(lokeys.EnableKMSOptions{Alias: alias, Region: region, Profile: profile, Apply: apply})
	if err != nil {
		return err
	}
	fmt.Println(message)
	return nil
}
