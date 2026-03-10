package main

import (
	"context"
	"flag"

	"github.com/google/subcommands"
	"lokeys/internal/lokeys"
)

type removeCommand struct{}

func (*removeCommand) Name() string     { return "remove" }
func (*removeCommand) Synopsis() string { return "remove a file from protection" }
func (*removeCommand) Usage() string {
	return "remove <path>\n\tRemove file from protection, restore original file if managed symlink, and cleanup managed copies.\n"
}
func (*removeCommand) SetFlags(*flag.FlagSet) {}
func (*removeCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	return runWithExitStatus(runRemove(f.Args()))
}

func runRemove(args []string) error {
	arg, err := requireOneArg(args, "remove", "path")
	if err != nil {
		return err
	}
	return lokeys.RunRemove(arg)
}
