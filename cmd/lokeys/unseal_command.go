package main

import (
	"context"
	"flag"

	"github.com/google/subcommands"
	"lokeys/internal/lokeys"
)

type unsealCommand struct {
}

func (*unsealCommand) Name() string     { return "unseal" }
func (*unsealCommand) Synopsis() string { return "decrypt all protected files to RAM disk" }
func (*unsealCommand) Usage() string {
	return "unseal\n\tDecrypt all protected files into RAM-disk storage.\n"
}
func (*unsealCommand) SetFlags(*flag.FlagSet) {}
func (c *unsealCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	return runWithExitStatus(runUnseal(f.Args()))
}

func runUnseal(args []string) error {
	if err := requireNoArgs(args, "unseal"); err != nil {
		return err
	}
	return lokeys.RunUnseal()
}
