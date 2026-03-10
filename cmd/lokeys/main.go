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

const (
	sessionFlagName = "session"
	sessionFlagHelp = "reuse encoded encryption key from $LOKEYS_SESSION_KEY for this process"
)

var version = "dev"

func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")
	subcommands.Register(&listCommand{}, "")
	subcommands.Register(&addCommand{}, "")
	subcommands.Register(&sealCommand{}, "")
	subcommands.Register(&unsealCommand{}, "")
	subcommands.Register(&backupCommand{}, "")
	subcommands.Register(&sessionExportCommand{}, "")
	if subcommands.DefaultCommander != nil {
		defaultExplain := subcommands.DefaultCommander.Explain
		subcommands.DefaultCommander.Explain = func(w io.Writer) {
			if defaultExplain != nil {
				defaultExplain(w)
			}
			fmt.Fprintln(w)
			fmt.Fprintf(w, "Session key mode: pass --session to any data command (add/list/seal/unseal) to use encoded key in %s.\n", lokeys.SessionKeyEnv)
			fmt.Fprintln(w, "Use `lokeys session-export` to print an export command for your shell session.")
			fmt.Fprintln(w, "Without --session, lokeys always prompts securely for the encryption key.")
		}
	}

	flag.Usage = usage
	flag.Parse()
	fmt.Fprintf(os.Stderr, "lokeys version %s\n", version)

	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
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

func registerSessionFlag(fs *flag.FlagSet, target *bool) {
	fs.BoolVar(target, sessionFlagName, false, sessionFlagHelp)
}
