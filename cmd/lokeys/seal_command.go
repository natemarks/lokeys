package main

import (
	"context"
	"flag"

	"github.com/google/subcommands"
	"lokeys/internal/lokeys"
)

type sealCommand struct {
}

func (*sealCommand) Name() string     { return "seal" }
func (*sealCommand) Synopsis() string { return "encrypt all protected RAM-disk files" }
func (*sealCommand) Usage() string {
	return "seal\n\tEncrypt all protected RAM-disk files into secure storage.\n"
}
func (*sealCommand) SetFlags(*flag.FlagSet) {}
func (c *sealCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	return runWithExitStatus(runSeal(f.Args()))
}

func runSeal(args []string) error {
	if err := requireNoArgs(args, "seal"); err != nil {
		return err
	}
	return lokeys.RunSeal()
}
