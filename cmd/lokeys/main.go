package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/google/subcommands"
	"lokeys/internal/lokeys"
)

var version = "dev"

func main() {
	registerCommands()
	if subcommands.DefaultCommander != nil {
		defaultExplain := subcommands.DefaultCommander.Explain
		subcommands.DefaultCommander.Explain = func(w io.Writer) {
			if defaultExplain != nil {
				defaultExplain(w)
			}
			fmt.Fprintln(w)
			fmt.Fprintf(w, "Key source: use encoded key in %s when set; otherwise lokeys prompts securely.\n", lokeys.SessionKeyEnv)
			fmt.Fprintln(w, "Use `lokeys session-export` to print an export command for your shell session.")
			fmt.Fprintln(w, "Quick start: eval \"$(lokeys session-export)\"")
		}
	}

	flag.Usage = usage
	flag.Parse()

	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}

func registerCommands() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")
	for _, cmd := range []subcommands.Command{
		&listCommand{},
		&addCommand{},
		&removeCommand{},
		&sealCommand{},
		&unsealCommand{},
		&backupCommand{},
		&restoreCommand{},
		&rotateCommand{},
		&sessionExportCommand{},
		&versionCommand{},
	} {
		subcommands.Register(cmd, "")
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "lokeys %s - manage protected files in RAM disk\n\n", version)
	if subcommands.DefaultCommander != nil && subcommands.DefaultCommander.Explain != nil {
		subcommands.DefaultCommander.Explain(os.Stderr)
	}
}

func usageError(message string) error {
	return fmt.Errorf("%w: %s", errUsage, message)
}

func runWithExitStatus(err error) subcommands.ExitStatus {
	if err == nil {
		return subcommands.ExitSuccess
	}
	if errors.Is(err, errUsage) {
		fmt.Fprintln(os.Stderr, err.Error())
		return subcommands.ExitUsageError
	}
	fmt.Fprintln(os.Stderr, err.Error())
	return subcommands.ExitFailure
}

var errUsage = errors.New("usage error")

func requireNoArgs(args []string, command string) error {
	if len(args) != 0 {
		return usageError(command + " takes no arguments")
	}
	return nil
}

func requireOneArg(args []string, command string, name string) (string, error) {
	if len(args) != 1 {
		return "", usageError(command + " requires a single " + name)
	}
	return args[0], nil
}

func requireZeroOrOneArg(args []string, command string, name string) (string, error) {
	if len(args) > 1 {
		return "", usageError(command + " accepts at most one " + name)
	}
	if len(args) == 0 {
		return "", nil
	}
	return args[0], nil
}
