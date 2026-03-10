package main

import (
	"context"
	"flag"

	"github.com/google/subcommands"
	"lokeys/internal/lokeys"
)

type listCommand struct {
	session bool
}

func (*listCommand) Name() string     { return "list" }
func (*listCommand) Synopsis() string { return "list protected files and integrity status" }
func (*listCommand) Usage() string {
	return "list [--session]\n\tList protected files and verify secure/insecure hashes.\n\t--session uses $LOKEYS_SESSION_KEY (encoded key) or prompts and stores encoded key for this run.\n"
}
func (c *listCommand) SetFlags(fs *flag.FlagSet) {
	registerSessionFlag(fs, &c.session)
}
func (c *listCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	return runWithExitStatus(runList(f.Args(), c.session))
}

func runList(args []string, session bool) error {
	if len(args) != 0 {
		return usageError("list takes no arguments")
	}
	return lokeys.RunList(session)
}
