package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/google/subcommands"
	"lokeys/internal/lokeys"
)

type sessionExportCommand struct{}

func (*sessionExportCommand) Name() string     { return "session-export" }
func (*sessionExportCommand) Synopsis() string { return "print shell export command for session key" }
func (*sessionExportCommand) Usage() string {
	return "session-export\n\tPrompt for key and print export command for $LOKEYS_SESSION_KEY.\n"
}
func (*sessionExportCommand) SetFlags(*flag.FlagSet) {}
func (*sessionExportCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if err := requireNoArgs(f.Args(), "session-export"); err != nil {
		return runWithExitStatus(err)
	}

	exportLine, err := lokeys.RunSessionExport()
	if err != nil {
		return runWithExitStatus(err)
	}

	fmt.Println(exportLine)
	return subcommands.ExitSuccess
}
