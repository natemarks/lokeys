package main

import (
	"context"
	"flag"
	"strings"

	"github.com/google/subcommands"
	"lokeys/internal/lokeys"
)

type sealCommand struct {
	allowKMSBypassFiles multiStringFlag
}

func (*sealCommand) Name() string     { return "seal" }
func (*sealCommand) Synopsis() string { return "encrypt all protected RAM-disk files" }
func (*sealCommand) Usage() string {
	return "seal\n\tEncrypt all protected RAM-disk files into secure storage.\n"
}
func (c *sealCommand) SetFlags(fs *flag.FlagSet) {
	fs.Var(&c.allowKMSBypassFiles, "allow-kms-bypass-file", "portable or absolute path for a discovered non-default $HOME/.aws/* file to bypass KMS; repeatable (config and credentials auto-bypass)")
}
func (c *sealCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	return runWithExitStatus(runSeal(f.Args(), c.allowKMSBypassFiles.values()))
}

func runSeal(args []string, allowKMSBypassFiles []string) error {
	if err := requireNoArgs(args, "seal"); err != nil {
		return err
	}
	if len(allowKMSBypassFiles) == 0 {
		return lokeys.RunSeal()
	}
	return lokeys.RunSealWithOptions(lokeys.SealOptions{AllowKMSBypassFiles: allowKMSBypassFiles})
}

type multiStringFlag []string

func (f *multiStringFlag) String() string {
	if f == nil {
		return ""
	}
	return strings.Join(*f, ",")
}

func (f *multiStringFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func (f *multiStringFlag) values() []string {
	if f == nil {
		return nil
	}
	return append([]string{}, *f...)
}
