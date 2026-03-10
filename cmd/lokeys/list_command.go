package main

import (
	"context"
	"flag"

	"github.com/google/subcommands"
	"lokeys/internal/lokeys"
)

type listCommand struct {
}

func (*listCommand) Name() string     { return "list" }
func (*listCommand) Synopsis() string { return "list protected files and integrity status" }
func (*listCommand) Usage() string {
	return "list\n\tList protected files and verify secure/insecure hashes.\n"
}
func (*listCommand) SetFlags(*flag.FlagSet) {}
func (c *listCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	return runWithExitStatus(runList(f.Args()))
}

func runList(args []string) error {
	if err := requireNoArgs(args, "list"); err != nil {
		return err
	}
	return lokeys.RunList()
}
