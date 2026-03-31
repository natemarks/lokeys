package main

import (
	"context"
	"flag"

	"github.com/google/subcommands"
	"lokeys/internal/lokeys"
)

type pauseCommand struct{}

func (*pauseCommand) Name() string     { return "pause" }
func (*pauseCommand) Synopsis() string { return "pause unseal for a managed file" }
func (*pauseCommand) Usage() string {
	return "pause <path>\n\tMark a managed file as paused so unseal skips extraction.\n"
}
func (*pauseCommand) SetFlags(*flag.FlagSet) {}
func (*pauseCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	return runWithExitStatus(runPause(f.Args()))
}

func runPause(args []string) error {
	arg, err := requireOneArg(args, "pause", "path")
	if err != nil {
		return err
	}
	return lokeys.RunPause(arg)
}
