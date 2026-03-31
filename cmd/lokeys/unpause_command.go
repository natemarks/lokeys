package main

import (
	"context"
	"flag"

	"github.com/google/subcommands"
	"lokeys/internal/lokeys"
)

type unpauseCommand struct{}

func (*unpauseCommand) Name() string     { return "unpause" }
func (*unpauseCommand) Synopsis() string { return "resume unseal for a managed file" }
func (*unpauseCommand) Usage() string {
	return "unpause <path>\n\tMark a managed file as unpaused so unseal includes extraction.\n"
}
func (*unpauseCommand) SetFlags(*flag.FlagSet) {}
func (*unpauseCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	return runWithExitStatus(runUnpause(f.Args()))
}

func runUnpause(args []string) error {
	arg, err := requireOneArg(args, "unpause", "path")
	if err != nil {
		return err
	}
	return lokeys.RunUnpause(arg)
}
