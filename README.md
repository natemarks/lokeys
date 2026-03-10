# lokeys

`lokeys` keeps small sensitive files encrypted at rest and only decrypted in RAM.

It works by:
- storing encrypted files in `~/.lokeys/secure`
- mounting a tmpfs RAM disk at `~/.lokeys/insecure`
- replacing original files with symlinks to the RAM-disk copies
- tracking protected paths in `~/.config/lokeys`

When you reboot, the RAM-disk contents disappear automatically.

## Requirements

- Linux with `tmpfs`
- `sudo` access (used to mount the RAM disk)

## Install (downloaded binary)

Assume you downloaded an executable named `lokeys` from a release.

```bash
mkdir -p "$HOME/.local/bin"
mv ./lokeys "$HOME/.local/bin/lokeys"
chmod 0755 "$HOME/.local/bin/lokeys"
```

Make sure `~/.local/bin` is on your `PATH`, then verify:

```bash
lokeys version
lokeys help
```

## Commands

- `lokeys add <path>`: protect a file, encrypt it, and replace original with a symlink to RAM
- `lokeys remove <path>`: unprotect a file and clean up managed copies
- `lokeys list`: show tracked files and integrity status
- `lokeys seal`: encrypt all tracked RAM-disk files back into secure storage
- `lokeys unseal`: decrypt tracked files into RAM and ensure symlinks are in place
- `lokeys backup`: create `~/.lokeys/secure/<epoch>.tar` backup
- `lokeys session-export`: print `export LOKEYS_SESSION_KEY='...'` for your shell
- `lokeys version`: print build/version string
- `lokeys help`: show usage and subcommands

## Key handling

- `lokeys` never stores encryption keys in config.
- You provide a passphrase (must be longer than 16 characters).
- Passphrase is converted to key material, and each encrypted file stores KDF metadata (scrypt params + salt) in its header.
- If `LOKEYS_SESSION_KEY` is set, lokeys uses it as the encoded key.
- If `LOKEYS_SESSION_KEY` is not set, lokeys prompts securely.

This means encrypted files are portable: move them to another machine and decrypt with the same passphrase.

Load a key into your current shell session:

```bash
eval "$(lokeys session-export)"
```

After that, subsequent commands in that shell do not prompt for key input.

## First-time round trip

1. Initialize state

```bash
lokeys list
```

This creates `~/.config/lokeys` and lokeys directories if missing.

2. Create a test secret file

```bash
mkdir -p "$HOME/secrets"
printf 'api-token-123\n' > "$HOME/secrets/demo.txt"
chmod 0600 "$HOME/secrets/demo.txt"
```

3. Protect it

```bash
lokeys add "$HOME/secrets/demo.txt"
```

You may be prompted for:
- encryption passphrase
- sudo password (for mounting tmpfs)

4. Check status

```bash
lokeys list
```

`list` prints a legend and status values:
- `OK`: secure and insecure hashes match
- `MISSING_INSECURE`: RAM copy missing
- `MISSING_SECURE`: encrypted copy missing
- `MISMATCH`: secure and insecure content differ

5. Seal changes after edits

```bash
lokeys seal
```

6. Restore decrypted working set

```bash
lokeys unseal
```

7. Create a backup tarball

```bash
lokeys backup
```

Backup includes:
- contents of `~/.lokeys/secure` (excluding the backup tar itself)
- `.config/lokeys` entry in the tar

8. Remove protection (optional)

```bash
lokeys remove "$HOME/secrets/demo.txt"
```

## Troubleshooting

- Wrong key in env var:
  - unset it and retry: `unset LOKEYS_SESSION_KEY`
- RAM-disk mount ownership problems:
  - `sudo umount "$HOME/.lokeys/insecure"`
  - rerun your command
- Non-interactive terminal key prompt failure:
  - export `LOKEYS_SESSION_KEY` first via `session-export`
