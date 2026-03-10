package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/subcommands"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const (
	configFileRel                   = ".config/lokeys"
	defaultDecryptedRel             = ".lokeys/insecure"
	defaultEncryptedRel             = ".lokeys/secure"
	defaultRamdiskSize              = "100m"
	defaultMountMode                = "0700"
	sessionKeyEnv                   = "LOKEYS_SESSION_KEY"
	sessionFlagName                 = "session"
	sessionFlagHelp                 = "reuse encoded encryption key from $LOKEYS_SESSION_KEY for this process"
	configFilePerm      os.FileMode = 0600
	dirPerm             os.FileMode = 0700
)

const fileMagic = "LOKEYS1"

var version = "dev"

type config struct {
	ProtectedFiles []string `json:"protectedFiles"`
}

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
			fmt.Fprintf(w, "Session key mode: pass --session to any data command (add/list/seal/unseal) to use encoded key in %s.\n", sessionKeyEnv)
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

func ensureConfig() (*config, bool, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, false, err
	}
	path := filepath.Join(home, configFileRel)
	_, statErr := os.Stat(path)
	if statErr == nil {
		cfg, err := readConfig(path)
		return cfg, false, err
	}
	if !os.IsNotExist(statErr) {
		return nil, false, statErr
	}

	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return nil, false, err
	}

	cfg := &config{ProtectedFiles: []string{}}
	if err := writeConfigTo(path, cfg); err != nil {
		return nil, false, err
	}
	return cfg, true, nil
}

func readConfig(path string) (*config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func writeConfig(cfg *config) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(home, configFileRel)
	return writeConfigTo(path, cfg)
}

func writeConfigTo(path string, cfg *config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, configFilePerm)
}

func keyForCommand(session bool) ([]byte, error) {
	if session {
		if envKey, ok := os.LookupEnv(sessionKeyEnv); ok && strings.TrimSpace(envKey) != "" {
			key, err := decodeEncodedKey(strings.TrimSpace(envKey))
			if err != nil {
				return nil, fmt.Errorf("%s must contain an encoded 32-byte key: %w", sessionKeyEnv, err)
			}
			return key, nil
		}
	}

	key, encoded, err := promptForKey()
	if err != nil {
		return nil, err
	}

	if session {
		if err := os.Setenv(sessionKeyEnv, encoded); err != nil {
			return nil, fmt.Errorf("set %s: %w", sessionKeyEnv, err)
		}
		fmt.Fprintf(os.Stderr, "session key loaded for this run; export %s in your shell to reuse across commands\n", sessionKeyEnv)
	}

	return key, nil
}

func promptForKey() ([]byte, string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, "", fmt.Errorf("encryption key required: run in a terminal")
	}
	fmt.Fprint(os.Stderr, "encryption key (>16 chars): ")
	secret, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, "", err
	}
	return deriveKeyFromPassphrase(strings.TrimSpace(string(secret)))
}

func decodeEncodedKey(raw string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid encoded session key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid encoded session key length: got %d bytes, want 32", len(key))
	}
	return key, nil
}

func deriveKeyFromPassphrase(raw string) ([]byte, string, error) {
	if len(raw) <= 16 {
		return nil, "", fmt.Errorf("encryption key must be more than 16 characters")
	}
	sum := sha256.Sum256([]byte(raw))
	key := make([]byte, len(sum))
	copy(key, sum[:])
	encoded := base64.StdEncoding.EncodeToString(key)
	return key, encoded, nil
}

func validateKeyForExistingProtectedFiles(cfg *config, key []byte) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	secureDir := filepath.Join(home, defaultEncryptedRel)

	for _, portable := range cfg.ProtectedFiles {
		fullPath, err := expandPortablePath(portable)
		if err != nil {
			return err
		}
		rel, err := relToHome(fullPath)
		if err != nil {
			return err
		}
		securePath := filepath.Join(secureDir, rel)
		if !fileExists(securePath) {
			continue
		}
		ciphertext, err := os.ReadFile(securePath)
		if err != nil {
			return err
		}
		if _, err := decryptBytes(ciphertext, key); err != nil {
			return fmt.Errorf("invalid encryption key for protected files")
		}
		return nil
	}

	return nil
}

func ensureEncryptedDir(path string) error {
	return os.MkdirAll(path, dirPerm)
}

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
	scanner := bufio.NewScanner(bytes.NewReader(data))
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

func expandUserPath(path string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if path == "~" {
		path = home
	} else if strings.HasPrefix(path, "~/") {
		path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
	}
	path = os.ExpandEnv(path)
	if !filepath.IsAbs(path) {
		path, err = filepath.Abs(path)
		if err != nil {
			return "", err
		}
	}
	return filepath.Clean(path), nil
}

func portablePath(path string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	path = filepath.Clean(path)
	if !strings.HasPrefix(path, home+string(os.PathSeparator)) && path != home {
		return "", fmt.Errorf("path must be under $HOME")
	}
	if path == home {
		return "$HOME", nil
	}
	return strings.Replace(path, home, "$HOME", 1), nil
}

func expandPortablePath(path string) (string, error) {
	if strings.HasPrefix(path, "$HOME") {
		return expandUserPath(strings.Replace(path, "$HOME", "~", 1))
	}
	return expandUserPath(path)
}

func relToHome(path string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(home, path)
	if err != nil {
		return "", err
	}
	if rel == "." || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("path must be under $HOME")
	}
	return rel, nil
}

func ensureParentDir(path string) error {
	return os.MkdirAll(filepath.Dir(path), dirPerm)
}

func ensureRegularFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("path is a symlink: %s", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("path is not a regular file: %s", path)
	}
	return nil
}

func copyFile(src, dst string, perm os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, perm)
}

func replaceWithSymlink(path string, target string) error {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			current, err := os.Readlink(path)
			if err != nil {
				return err
			}
			if current == target {
				return nil
			}
			return fmt.Errorf("symlink points elsewhere: %s", path)
		}
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Symlink(target, path)
}

func encryptFile(src, dst string, key []byte) error {
	plaintext, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	ciphertext, err := encryptBytes(plaintext, key)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, ciphertext, 0600)
}

func decryptFile(src, dst string, key []byte) error {
	ciphertext, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	plaintext, err := decryptBytes(ciphertext, key)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, plaintext, 0600)
}

func encryptBytes(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	buf := bytes.NewBuffer(nil)
	buf.WriteString(fileMagic)
	buf.Write(nonce)
	buf.Write(ciphertext)
	return buf.Bytes(), nil
}

func decryptBytes(ciphertext []byte, key []byte) ([]byte, error) {
	if len(ciphertext) < len(fileMagic) {
		return nil, fmt.Errorf("ciphertext too short")
	}
	if string(ciphertext[:len(fileMagic)]) != fileMagic {
		return nil, fmt.Errorf("invalid ciphertext header")
	}
	ciphertext = ciphertext[len(fileMagic):]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := ciphertext[:nonceSize]
	enc := ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, enc, nil)
}

func sha256File(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum), nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func hashOrMissing(value string) string {
	if value == "" {
		return "MISSING"
	}
	return value
}

func registerSessionFlag(fs *flag.FlagSet, target *bool) {
	fs.BoolVar(target, sessionFlagName, false, sessionFlagHelp)
}

func containsString(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}
