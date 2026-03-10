# lokeys

`lokeys` protects small sensitive files by:

- keeping decrypted copies in a tmpfs RAM disk at `~/.lokeys/insecure`
- storing encrypted copies at `~/.lokeys/secure`
- tracking protected paths in `~/.config/lokeys`

## Install

Requirements:

- Go 1.25+
- Linux with `tmpfs` mount support
- `sudo` access for mounting tmpfs

Build locally:

```bash
go build -ldflags "-X main.version=$(git rev-parse HEAD)" -o ./bin/lokeys ./cmd/lokeys
```

Optional install to your Go bin path:

```bash
go install ./cmd/lokeys
```

## Commands

- `lokeys list` - list tracked files and integrity status
- `lokeys add <path>` - add a file to protection, encrypt it, and replace original with symlink to RAM-disk copy
- `lokeys remove <path>` - remove a file from protection and clean up managed copies
- `lokeys seal` - encrypt all tracked RAM-disk files to secure storage
- `lokeys unseal` - decrypt all tracked files into RAM disk and ensure symlinks point there
- `lokeys backup` - create `<epoch>.tar` backup in `~/.lokeys/secure` containing secure files and `.config/lokeys`
- `lokeys session-export` - prompt once and print an `export LOKEYS_SESSION_KEY=...` line for your shell
- `lokeys version` - print the build/version string
- `lokeys help` - show command help

## Key handling

- `lokeys` never stores encryption keys in config files.
- You enter a passphrase (must be more than 16 characters).
- The passphrase is deterministically encoded into a 32-byte AES key (SHA-256, base64-encoded for env storage).
- If `LOKEYS_SESSION_KEY` is set, lokeys uses it as the encoded key value.
- If `LOKEYS_SESSION_KEY` is not set, lokeys prompts securely for your passphrase.

To persist session key across multiple commands in your current shell:

```bash
eval "$(./bin/lokeys session-export)"
```

Then run commands and it will not re-prompt while that env var remains set.

## Fresh install round trip

1) Build binary

```bash
go build -ldflags "-X main.version=$(git rev-parse HEAD)" -o ./bin/lokeys ./cmd/lokeys
```

2) Initialize and inspect state

```bash
./bin/lokeys list
```

This creates `~/.config/lokeys` and ensures storage directories exist.

3) Create a test secret file

```bash
mkdir -p ~/secrets
printf 'api-token-123\n' > ~/secrets/demo.txt
chmod 600 ~/secrets/demo.txt
```

4) Add file to lokeys

```bash
./bin/lokeys add ~/secrets/demo.txt
```

You will be prompted for:

- encryption passphrase
- sudo password (to mount tmpfs when needed)

5) Verify status

```bash
./bin/lokeys list
```

You should see `OK` for the tracked file.
`list` also prints a short legend for status values.

6) Seal and unseal lifecycle

```bash
./bin/lokeys seal
./bin/lokeys unseal
```

Optional: remove protection and restore managed symlinked file

```bash
./bin/lokeys remove ~/secrets/demo.txt
```

7) Create a secure storage backup tarball

```bash
./bin/lokeys backup
```

This writes a file like `~/.lokeys/secure/1710076800.tar` and includes:

- encrypted files from `~/.lokeys/secure` (excluding the tarball itself)
- `.config/lokeys`

8) Optional: avoid repeated key prompts in one shell session

```bash
eval "$(./bin/lokeys session-export)"
./bin/lokeys list
./bin/lokeys seal
./bin/lokeys unseal
```

## Notes

- `LOKEYS_SESSION_KEY` must contain an encoded 32-byte key.
- If key validation fails against existing encrypted files, commands fail fast.
- If tmpfs is mounted with wrong ownership, unmount and retry:

```bash
sudo umount ~/.lokeys/insecure
```
