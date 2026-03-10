package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/google/subcommands"
)

type versionCommand struct{}

func (*versionCommand) Name() string     { return "version" }
func (*versionCommand) Synopsis() string { return "print lokeys version" }
func (*versionCommand) Usage() string {
	return "version\n\tPrint build/version string.\n"
}
func (*versionCommand) SetFlags(*flag.FlagSet) {}
func (*versionCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if err := requireNoArgs(f.Args(), "version"); err != nil {
		return runWithExitStatus(err)
	}
	fmt.Println(version)
	return subcommands.ExitSuccess
}
