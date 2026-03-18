package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/google/subcommands"
	"lokeys/internal/lokeys"
)

type rotateCommand struct{}

func (*rotateCommand) Name() string     { return "rotate" }
func (*rotateCommand) Synopsis() string { return "rotate encryption key for secure files" }
func (*rotateCommand) Usage() string {
	return "rotate\n\tRotate encrypted storage to a newly prompted key, with pre-rotation backup.\n"
}
func (*rotateCommand) SetFlags(*flag.FlagSet) {}
func (c *rotateCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	return runWithExitStatus(runRotate(f.Args()))
}

func runRotate(args []string) error {
	if err := requireNoArgs(args, "rotate"); err != nil {
		return err
	}
	backupPath, rotated, err := lokeys.RunRotate()
	if err != nil {
		return err
	}
	fmt.Printf("backup created: %s\n", backupPath)
	fmt.Printf("rotated encrypted files: %d\n", rotated)
	return nil
}
