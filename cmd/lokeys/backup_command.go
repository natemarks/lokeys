package main

import (
	"archive/tar"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/google/subcommands"
)

type backupCommand struct{}

func (*backupCommand) Name() string     { return "backup" }
func (*backupCommand) Synopsis() string { return "archive secure storage to tarball" }
func (*backupCommand) Usage() string {
	return "backup\n\tPack contents of secure storage into timestamped tar in secure folder.\n"
}
func (*backupCommand) SetFlags(*flag.FlagSet) {}
func (*backupCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	return runWithExitStatus(runBackup(f.Args()))
}

func runBackup(args []string) error {
	if len(args) != 0 {
		return usageError("backup takes no arguments")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	if _, _, err := ensureConfig(); err != nil {
		return err
	}
	secureDir := filepath.Join(home, defaultEncryptedRel)
	configPath := filepath.Join(home, configFileRel)
	if err := ensureEncryptedDir(secureDir); err != nil {
		return err
	}

	backupName := fmt.Sprintf("%d.tar", time.Now().Unix())
	backupPath := filepath.Join(secureDir, backupName)

	out, err := os.OpenFile(backupPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out.Close()

	tw := tar.NewWriter(out)
	defer tw.Close()

	if err := filepath.WalkDir(secureDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == secureDir {
			return nil
		}
		if path == backupPath {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}
		if !d.IsDir() && !info.Mode().IsRegular() {
			return nil
		}

		relPath, err := filepath.Rel(secureDir, path)
		if err != nil {
			return err
		}

		head, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		head.Name = filepath.ToSlash(relPath)

		if d.IsDir() {
			head.Name += "/"
		}

		if err := tw.WriteHeader(head); err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		in, err := os.Open(path)
		if err != nil {
			return err
		}
		if _, err := io.Copy(tw, in); err != nil {
			in.Close()
			return err
		}
		if err := in.Close(); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}

	if err := addFileToTar(tw, configPath, filepath.ToSlash(configFileRel)); err != nil {
		return err
	}

	fmt.Printf("backup created: %s\n", backupPath)
	return nil
}

func addFileToTar(tw *tar.Writer, absPath string, tarPath string) error {
	info, err := os.Stat(absPath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file: %s", absPath)
	}

	head, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	head.Name = tarPath
	if err := tw.WriteHeader(head); err != nil {
		return err
	}

	in, err := os.Open(absPath)
	if err != nil {
		return err
	}
	if _, err := io.Copy(tw, in); err != nil {
		in.Close()
		return err
	}
	if err := in.Close(); err != nil {
		return err
	}
	return nil
}
