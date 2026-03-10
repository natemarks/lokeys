package main

import (
	"context"
	"flag"
	"os"
	"path/filepath"

	"github.com/google/subcommands"
)

type sealCommand struct {
	session bool
}

func (*sealCommand) Name() string     { return "seal" }
func (*sealCommand) Synopsis() string { return "encrypt all protected RAM-disk files" }
func (*sealCommand) Usage() string {
	return "seal [--session]\n\tEncrypt all protected RAM-disk files into secure storage.\n\t--session reuses key from $LOKEYS_SESSION_KEY or prompts once and stores it for this process.\n"
}
func (c *sealCommand) SetFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.session, "session", false, "reuse encryption key from $LOKEYS_SESSION_KEY for this process")
}
func (c *sealCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	return runWithExitStatus(runSeal(f.Args(), c.session))
}

func runSeal(args []string, session bool) error {
	if len(args) != 0 {
		return usageError("seal takes no arguments")
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

		if err := ensureParentDir(securePath); err != nil {
			return err
		}
		if err := encryptFile(insecurePath, securePath, key); err != nil {
			return err
		}
	}

	return nil
}
