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
	"strings"

	"github.com/google/subcommands"
	"golang.org/x/term"
)

const (
	configFileRel                   = ".config/lokeys"
	defaultDecryptedRel             = ".lokeys/insecure"
	defaultEncryptedRel             = ".lokeys/secure"
	defaultRamdiskSize              = "100m"
	defaultMountMode                = "0700"
	configFilePerm      os.FileMode = 0600
	dirPerm             os.FileMode = 0700
)

const fileMagic = "LOKEYS1"

var version = "dev"

type config struct {
	ProtectedFiles []string `json:"protectedFiles"`
	Key            string   `json:"key"`
}

func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")
	subcommands.Register(&listCommand{}, "")
	subcommands.Register(&addCommand{}, "")
	subcommands.Register(&sealCommand{}, "")
	subcommands.Register(&unsealCommand{}, "")

	flag.Usage = usage
	flag.Parse()

	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}

func usage() {
	fmt.Fprintf(os.Stderr, "lokeys %s - manage protected files in RAM disk\n\n", version)
	if subcommands.DefaultCommander != nil && subcommands.DefaultCommander.Explain != nil {
		subcommands.DefaultCommander.Explain(os.Stderr)
	}
}

type listCommand struct{}

func (*listCommand) Name() string     { return "list" }
func (*listCommand) Synopsis() string { return "list protected files and integrity status" }
func (*listCommand) Usage() string {
	return "list\n\tList protected files and verify secure/insecure hashes.\n"
}
func (*listCommand) SetFlags(*flag.FlagSet) {}
func (*listCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	return runWithExitStatus(runList(f.Args()))
}

type addCommand struct{}

func (*addCommand) Name() string     { return "add" }
func (*addCommand) Synopsis() string { return "add a file to protected set" }
func (*addCommand) Usage() string {
	return "add <path>\n\tAdd file to protected set and replace with RAM-disk symlink.\n"
}
func (*addCommand) SetFlags(*flag.FlagSet) {}
func (*addCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	return runWithExitStatus(runAdd(f.Args()))
}

type sealCommand struct{}

func (*sealCommand) Name() string     { return "seal" }
func (*sealCommand) Synopsis() string { return "encrypt all protected RAM-disk files" }
func (*sealCommand) Usage() string {
	return "seal\n\tEncrypt all protected RAM-disk files into secure storage.\n"
}
func (*sealCommand) SetFlags(*flag.FlagSet) {}
func (*sealCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	return runWithExitStatus(runSeal(f.Args()))
}

type unsealCommand struct{}

func (*unsealCommand) Name() string     { return "unseal" }
func (*unsealCommand) Synopsis() string { return "decrypt all protected files to RAM disk" }
func (*unsealCommand) Usage() string {
	return "unseal\n\tDecrypt all protected files into RAM-disk storage.\n"
}
func (*unsealCommand) SetFlags(*flag.FlagSet) {}
func (*unsealCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	return runWithExitStatus(runUnseal(f.Args()))
}

func runList(args []string) error {
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
	if err := ensureRamdiskMounted(insecureDir); err != nil {
		return err
	}

	if len(config.ProtectedFiles) == 0 {
		fmt.Println("No protected files found.")
		return nil
	}

	key, err := configKey(config)
	if err != nil {
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

func runAdd(args []string) error {
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
	key, err := configKey(config)
	if err != nil {
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

func runSeal(args []string) error {
	if len(args) != 0 {
		return usageError("seal takes no arguments")
	}

	config, _, err := ensureConfig()
	if err != nil {
		return err
	}
	key, err := configKey(config)
	if err != nil {
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

func runUnseal(args []string) error {
	if len(args) != 0 {
		return usageError("unseal takes no arguments")
	}

	config, _, err := ensureConfig()
	if err != nil {
		return err
	}
	key, err := configKey(config)
	if err != nil {
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
	if _, err := os.Stat(path); err == nil {
		cfg, err := readConfig(path)
		return cfg, false, err
	}
	if !os.IsNotExist(err) {
		return nil, false, err
	}

	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return nil, false, err
	}

	key, err := randomKey()
	if err != nil {
		return nil, false, err
	}
	cfg := &config{ProtectedFiles: []string{}, Key: key}
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

func configKey(cfg *config) ([]byte, error) {
	if cfg.Key == "" {
		key, err := randomKey()
		if err != nil {
			return nil, err
		}
		cfg.Key = key
		if err := writeConfig(cfg); err != nil {
			return nil, err
		}
	}
	return base64.StdEncoding.DecodeString(cfg.Key)
}

func randomKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

func ensureEncryptedDir(path string) error {
	return os.MkdirAll(path, dirPerm)
}

func ensureRamdiskMounted(path string) error {
	if err := os.MkdirAll(path, dirPerm); err != nil {
		return err
	}
	if isMounted(path) {
		return nil
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
	cmd := exec.Command("sudo", "-S", "mount", "-t", "tmpfs", "-o", fmt.Sprintf("size=%s,mode=%s", defaultRamdiskSize, defaultMountMode), "tmpfs", path)
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

func containsString(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}
