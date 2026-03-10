package main

import (
	"context"
	"flag"

	"github.com/google/subcommands"
	"lokeys/internal/lokeys"
)

type unsealCommand struct {
	session bool
}

func (*unsealCommand) Name() string     { return "unseal" }
func (*unsealCommand) Synopsis() string { return "decrypt all protected files to RAM disk" }
func (*unsealCommand) Usage() string {
	return "unseal [--session]\n\tDecrypt all protected files into RAM-disk storage.\n\t--session uses $LOKEYS_SESSION_KEY (encoded key) or prompts and stores encoded key for this run.\n"
}
func (c *unsealCommand) SetFlags(fs *flag.FlagSet) {
	registerSessionFlag(fs, &c.session)
}
func (c *unsealCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	return runWithExitStatus(runUnseal(f.Args(), c.session))
}

func runUnseal(args []string, session bool) error {
	if len(args) != 0 {
		return usageError("unseal takes no arguments")
	}
	return lokeys.RunUnseal(session)
}
