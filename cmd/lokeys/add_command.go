package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/subcommands"
)

type addCommand struct {
	session bool
}

func (*addCommand) Name() string     { return "add" }
func (*addCommand) Synopsis() string { return "add a file to protected set" }
func (*addCommand) Usage() string {
	return "add <path>\n\tAdd file to protected set and replace with RAM-disk symlink.\n"
}
func (c *addCommand) SetFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.session, "session", false, "reuse encryption key from $LOKEYS_SESSION_KEY for this process")
}
func (c *addCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	return runWithExitStatus(runAdd(f.Args(), c.session))
}

func runAdd(args []string, session bool) error {
	if len(args) != 1 {
		return usageError("add requires a single path")
	}

	input := args[0]
	fullPath, err := expandUserPath(input)
	if err != nil {
		return err
	}

	config, _, err := ensureConfig()
	if err != nil {
		return err
	}
	key, err := keyForCommand(session)
	if err != nil {
		return err
	}
	if err := validateKeyForExistingProtectedFiles(config, key); err != nil {
		return err
	}

	portable, err := portablePath(fullPath)
	if err != nil {
		return err
	}

	if containsString(config.ProtectedFiles, portable) {
		fmt.Printf("%s already protected.\n", portable)
		return nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	secureDir := filepath.Join(home, defaultEncryptedRel)
	insecureDir := filepath.Join(home, defaultDecryptedRel)

	if err := ensureEncryptedDir(secureDir); err != nil {
		return err
	}
	if err := ensureRamdiskMounted(insecureDir); err != nil {
		return err
	}

	if err := ensureRegularFile(fullPath); err != nil {
		return err
	}

	rel, err := relToHome(fullPath)
	if err != nil {
		return err
	}

	securePath := filepath.Join(secureDir, rel)
	insecurePath := filepath.Join(insecureDir, rel)

	if err := ensureParentDir(insecurePath); err != nil {
		return err
	}
	if err := ensureParentDir(securePath); err != nil {
		return err
	}

	if err := copyFile(fullPath, insecurePath, 0600); err != nil {
		return err
	}
	if err := encryptFile(insecurePath, securePath, key); err != nil {
		return err
	}

	if err := replaceWithSymlink(fullPath, insecurePath); err != nil {
		return err
	}

	config.ProtectedFiles = append(config.ProtectedFiles, portable)
	return writeConfig(config)
}
