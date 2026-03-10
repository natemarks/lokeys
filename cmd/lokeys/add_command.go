package main

import (
	"context"
	"flag"

	"github.com/google/subcommands"
	"lokeys/internal/lokeys"
)

type addCommand struct {
	session bool
}

func (*addCommand) Name() string     { return "add" }
func (*addCommand) Synopsis() string { return "add a file to protected set" }
func (*addCommand) Usage() string {
	return "add [--session] <path>\n\tAdd file to protected set and replace with RAM-disk symlink.\n\t--session uses $LOKEYS_SESSION_KEY (encoded key) or prompts and stores encoded key for this run.\n"
}
func (c *addCommand) SetFlags(fs *flag.FlagSet) {
	registerSessionFlag(fs, &c.session)
}
func (c *addCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	return runWithExitStatus(runAdd(f.Args(), c.session))
}

func runAdd(args []string, session bool) error {
	if len(args) != 1 {
		return usageError("add requires a single path")
	}
	return lokeys.RunAdd(args[0], session)
}
