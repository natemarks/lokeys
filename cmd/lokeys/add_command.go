package main

import (
	"context"
	"flag"

	"github.com/google/subcommands"
	"lokeys/internal/lokeys"
)

type addCommand struct {
	allowKMSBypass bool
}

func (*addCommand) Name() string     { return "add" }
func (*addCommand) Synopsis() string { return "add a file to protected set" }
func (*addCommand) Usage() string {
	return "add <path>\n\tAdd file to protected set and replace with RAM-disk symlink.\n"
}
func (c *addCommand) SetFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.allowKMSBypass, "allow-kms-bypass", false, "allow bypassing KMS envelope for this one $HOME/.aws/* file")
}
func (c *addCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	return runWithExitStatus(runAdd(f.Args(), c.allowKMSBypass))
}

func runAdd(args []string, allowKMSBypass bool) error {
	arg, err := requireOneArg(args, "add", "path")
	if err != nil {
		return err
	}
	if !allowKMSBypass {
		return lokeys.RunAdd(arg)
	}
	return lokeys.RunAddWithOptions(arg, lokeys.AddOptions{AllowKMSBypass: allowKMSBypass})
}
