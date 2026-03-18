package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/google/subcommands"
	"lokeys/internal/lokeys"
)

type restoreCommand struct{}

func (*restoreCommand) Name() string { return "restore" }
func (*restoreCommand) Synopsis() string {
	return "restore secure storage and config from backup archive"
}
func (*restoreCommand) Usage() string {
	return "restore [archive.tar.gz]\n\tRestore secure content + config from archive (defaults to latest in secure dir).\n"
}
func (*restoreCommand) SetFlags(*flag.FlagSet) {}
func (c *restoreCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	return runWithExitStatus(runRestore(f.Args()))
}

func runRestore(args []string) error {
	archiveArg, err := requireZeroOrOneArg(args, "restore", "archive")
	if err != nil {
		return err
	}
	archivePath, restored, err := lokeys.RunRestore(archiveArg)
	if err != nil {
		return err
	}
	fmt.Printf("restored from: %s\n", archivePath)
	fmt.Printf("restored encrypted files: %d\n", restored)
	return nil
}
