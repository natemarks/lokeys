package main

import (
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/subcommands"
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

	config, created, err := ensureConfig()
	if err != nil {
		return err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	configPath := filepath.Join(home, configFileRel)
	secureDir := filepath.Join(home, defaultEncryptedRel)
	insecureDir := filepath.Join(home, defaultDecryptedRel)

	if created {
		fmt.Printf("No protected files found. Creating config at %s, encrypted storage at %s, and mounting a 100MB RAM disk at %s.\n", configPath, secureDir, insecureDir)
		if err := ensureEncryptedDir(secureDir); err != nil {
			return err
		}
		if err := ensureRamdiskMounted(insecureDir); err != nil {
			return err
		}
		return nil
	}

	if err := ensureEncryptedDir(secureDir); err != nil {
		return err
	}

	if len(config.ProtectedFiles) == 0 {
		fmt.Println("No protected files found.")
		return nil
	}

	key, err := keyForCommand(session)
	if err != nil {
		return err
	}
	if err := validateKeyForExistingProtectedFiles(config, key); err != nil {
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

		var insecureHash, secureHash string
		insecureExists := fileExists(insecurePath)
		secureExists := fileExists(securePath)

		if insecureExists {
			insecureHash, err = sha256File(insecurePath)
			if err != nil {
				return err
			}
		}

		if secureExists {
			ciphertext, err := os.ReadFile(securePath)
			if err != nil {
				return err
			}
			plaintext, err := decryptBytes(ciphertext, key)
			if err != nil {
				return err
			}
			secureHash = fmt.Sprintf("%x", sha256.Sum256(plaintext))
		}

		status := "OK"
		if !insecureExists {
			status = "MISSING_INSECURE"
		} else if !secureExists {
			status = "MISSING_SECURE"
		} else if insecureHash != secureHash {
			status = "MISMATCH"
		}

		fmt.Printf("%s  insecure=%s  secure=%s  %s\n", portable, hashOrMissing(insecureHash), hashOrMissing(secureHash), status)
	}

	return nil
}
