package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/google/subcommands"
	"lokeys/internal/lokeys"
)

type backupCommand struct{}

func (*backupCommand) Name() string     { return "backup" }
func (*backupCommand) Synopsis() string { return "archive secure storage to tarball" }
func (*backupCommand) Usage() string {
	return "backup\n\tPack contents of secure storage into timestamped tar in secure folder.\n"
}
func (*backupCommand) SetFlags(*flag.FlagSet) {}
func (*backupCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	return runWithExitStatus(runBackup(f.Args()))
}

func runBackup(args []string) error {
	if len(args) != 0 {
		return usageError("backup takes no arguments")
	}
	backupPath, err := lokeys.RunBackup()
	if err != nil {
		return err
	}
	fmt.Printf("backup created: %s\n", backupPath)
	return nil
}
