package main

import (
	"context"
	"flag"

	"github.com/google/subcommands"
	"lokeys/internal/lokeys"
)

type sealCommand struct {
	session bool
}

func (*sealCommand) Name() string     { return "seal" }
func (*sealCommand) Synopsis() string { return "encrypt all protected RAM-disk files" }
func (*sealCommand) Usage() string {
	return "seal [--session]\n\tEncrypt all protected RAM-disk files into secure storage.\n\t--session uses $LOKEYS_SESSION_KEY (encoded key) or prompts and stores encoded key for this run.\n"
}
func (c *sealCommand) SetFlags(fs *flag.FlagSet) {
	registerSessionFlag(fs, &c.session)
}
func (c *sealCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	return runWithExitStatus(runSeal(f.Args(), c.session))
}

func runSeal(args []string, session bool) error {
	if len(args) != 0 {
		return usageError("seal takes no arguments")
	}
	return lokeys.RunSeal(session)
}
