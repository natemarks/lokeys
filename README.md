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

- `lokeys list [--session]` - list tracked files and integrity status
- `lokeys add [--session] <path>` - add a file to protection, encrypt it, and replace original with symlink to RAM-disk copy
- `lokeys seal [--session]` - encrypt all tracked RAM-disk files to secure storage
- `lokeys unseal [--session]` - decrypt all tracked files into RAM disk and ensure symlinks point there
- `lokeys session-export` - prompt once and print an `export LOKEYS_SESSION_KEY=...` line for your shell
- `lokeys help` - show command help

## Key handling

- `lokeys` never stores encryption keys in config files.
- You enter a passphrase (must be more than 16 characters).
- The passphrase is deterministically encoded into a 32-byte AES key (SHA-256, base64-encoded for env storage).
- `--session` mode uses `LOKEYS_SESSION_KEY` as the encoded key value.

To persist session key across multiple commands in your current shell:

```bash
eval "$(./bin/lokeys session-export)"
```

Then run commands with `--session` and it will not re-prompt.

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

6) Seal and unseal lifecycle

```bash
./bin/lokeys seal
./bin/lokeys unseal
```

7) Optional: avoid repeated key prompts in one shell session

```bash
eval "$(./bin/lokeys session-export)"
./bin/lokeys list --session
./bin/lokeys seal --session
./bin/lokeys unseal --session
```

## Notes

- `LOKEYS_SESSION_KEY` must contain an encoded 32-byte key.
- If key validation fails against existing encrypted files, commands fail fast.
- If tmpfs is mounted with wrong ownership, unmount and retry:

```bash
sudo umount ~/.lokeys/insecure
```
