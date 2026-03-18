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

- `lokeys add <path>`: protect a file and store plaintext only on RAM disk
- `lokeys remove <path>`: unprotect a file and clean up managed copies
- `lokeys list`: show tracked files and integrity status
- `lokeys seal`: encrypt tracked RAM-disk files and auto-protect new RAM-disk files
- `lokeys unseal`: decrypt tracked files into RAM and ensure symlinks are in place
- `lokeys backup`: create `~/.lokeys/secure/<epoch>.tar.gz` backup
- `lokeys rotate`: rotate encrypted storage from old key to new key
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

## Key rotation

Use `rotate` to migrate all encrypted files to a newly prompted key.

```bash
lokeys rotate
```

Rotation flow:

- Uses old key from `LOKEYS_SESSION_KEY` when set; otherwise prompts for old key and validates it.
- Encrypts each new rotated ciphertext from RAM-disk plaintext when available (`~/.lokeys/insecure/<rel>`), so unsaved RAM edits are included.
- Synchronizes tracked RAM-disk files into secure storage with the old key, then creates a `backup` before re-encryption.
- Prompts for a new key and verifies each temp rotated file decrypts correctly with the new key before replacing old ciphertext.

8. Remove protection (optional)

```bash
lokeys remove "$HOME/secrets/demo.txt"
```

## RAM-disk-created files

You can now create new files directly under `~/.lokeys/insecure` and protect them without moving them first.

### `add` behavior for RAM-disk files

- If `add` receives a path under `~/.lokeys/insecure/<rel>`, lokeys derives the canonical tracked path as `$HOME/<rel>`.
- If `$HOME/<rel>` already exists, `add` fails to avoid overwriting an existing home file.
- If `$HOME/<rel>` does not exist, lokeys:
  - encrypts `~/.lokeys/insecure/<rel>` to `~/.lokeys/secure/<rel>`
  - creates `$HOME/<rel>` as a symlink to `~/.lokeys/insecure/<rel>`
  - tracks `$HOME/<rel>` in config

Example:

```bash
mkdir -p "$HOME/.lokeys/insecure/new/project"
printf 'draft-secret\n' > "$HOME/.lokeys/insecure/new/project/token.txt"
lokeys add "$HOME/.lokeys/insecure/new/project/token.txt"
```

### `seal` behavior for RAM-disk files

- `seal` still encrypts all currently tracked files.
- `seal` also scans `~/.lokeys/insecure` for regular files that are not yet tracked.
- For each untracked RAM-disk file at `<rel>`, lokeys compares against `$HOME/<rel>`:
  - if `$HOME/<rel>` exists, `seal` fails immediately (fail-fast on first conflict)
  - if `$HOME/<rel>` does not exist, lokeys protects that file using `<rel>` and tracks it

## Troubleshooting

- Wrong key in env var:
  - unset it and retry: `unset LOKEYS_SESSION_KEY`
- RAM-disk mount ownership problems:
  - `sudo umount "$HOME/.lokeys/insecure"`
  - rerun your command
- Non-interactive terminal key prompt failure:
  - export `LOKEYS_SESSION_KEY` first via `session-export`
