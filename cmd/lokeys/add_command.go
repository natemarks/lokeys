package main

import (
	"context"
	"flag"

	"github.com/google/subcommands"
	"lokeys/internal/lokeys"
)

type addCommand struct {
}

func (*addCommand) Name() string     { return "add" }
func (*addCommand) Synopsis() string { return "add a file to protected set" }
func (*addCommand) Usage() string {
	return "add <path>\n\tAdd file to protected set and replace with RAM-disk symlink.\n"
}
func (*addCommand) SetFlags(*flag.FlagSet) {}
func (c *addCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	return runWithExitStatus(runAdd(f.Args()))
}

func runAdd(args []string) error {
	arg, err := requireOneArg(args, "add", "path")
	if err != nil {
		return err
	}
	return lokeys.RunAdd(arg)
}
