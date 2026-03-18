package lokeys

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

func ensureRamdiskMounted(path string) error {
	if err := os.MkdirAll(path, dirPerm); err != nil {
		return err
	}
	if isMounted(path) {
		if err := unix.Access(path, unix.W_OK|unix.X_OK); err == nil {
			return nil
		}
		return fmt.Errorf("ramdisk mounted at %s is not writable by the current user; unmount and retry: sudo umount %s", path, path)
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("sudo password required: run in a terminal")
	}
	fmt.Print("sudo password: ")
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return err
	}
	mountOpts := fmt.Sprintf("size=%s,mode=%s,uid=%s,gid=%s", defaultRamdiskSize, defaultMountMode, strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid()))
	cmd := exec.Command("sudo", "-S", "mount", "-t", "tmpfs", "-o", mountOpts, "tmpfs", path)
	cmd.Stdin = bytes.NewReader(append(pass, '\n'))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("mount failed: %w", err)
	}
	return nil
}

func isMounted(path string) bool {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false
	}
	return isMountedInProcMounts(string(data), path)
}

func isMountedInProcMounts(procMounts string, path string) bool {
	scanner := bufio.NewScanner(strings.NewReader(procMounts))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		if fields[1] == path {
			return true
		}
	}
	return false
}
