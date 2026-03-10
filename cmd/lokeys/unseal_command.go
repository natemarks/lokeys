package main

import (
	"context"
	"flag"
	"os"
	"path/filepath"

	"github.com/google/subcommands"
)

type unsealCommand struct {
	session bool
}

func (*unsealCommand) Name() string     { return "unseal" }
func (*unsealCommand) Synopsis() string { return "decrypt all protected files to RAM disk" }
func (*unsealCommand) Usage() string {
	return "unseal\n\tDecrypt all protected files into RAM-disk storage.\n"
}
func (c *unsealCommand) SetFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.session, "session", false, "reuse encryption key from $LOKEYS_SESSION_KEY for this process")
}
func (c *unsealCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	return runWithExitStatus(runUnseal(f.Args(), c.session))
}

func runUnseal(args []string, session bool) error {
	if len(args) != 0 {
		return usageError("unseal takes no arguments")
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

	for _, portable := range config.ProtectedFiles {
		fullPath, err := expandPortablePath(portable)
		if err != nil {
			return err
		}
		rel, err := relToHome(fullPath)
		if err != nil {
			return err
		}
		insecurePath := filepath.Join(insecureDir, rel)
		securePath := filepath.Join(secureDir, rel)

		if err := ensureParentDir(insecurePath); err != nil {
			return err
		}
		if err := decryptFile(securePath, insecurePath, key); err != nil {
			return err
		}
		if err := replaceWithSymlink(fullPath, insecurePath); err != nil {
			return err
		}
	}

	return nil
}
