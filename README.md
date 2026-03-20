# lokeys

`lokeys` protects sensitive local files by combining three layers:

- encryption at rest in `~/.lokeys/secure`
- decrypted working copies only in a RAM disk at `~/.lokeys/insecure`
- optional AWS KMS envelope encryption (CMK) around lokeys ciphertext

## Why this model is useful

Many secrets (SSH keys, API tokens, cloud credentials) need to exist locally, but
plain files on disk increase risk from disk theft, backups, snapshot leaks, and
forensic recovery.

`lokeys` reduces that risk by:

- keeping encrypted files on persistent storage
- keeping plaintext in volatile memory-backed tmpfs only while in use
- optionally requiring AWS KMS CMK access for non-bypassed files

Result: better protection against offline exposure, while keeping a practical CLI
workflow for day-to-day development.

Default behavior is local-only encryption (no AWS KMS). KMS is optional and only
used after you explicitly run `lokeys enable-kms --apply`.

## Requirements

- Linux with `tmpfs`
- `sudo` access (for mounting the RAM disk)

## Install (downloaded binary)

Assume you downloaded an executable named `lokeys`.

```bash
mkdir -p "$HOME/.local/bin"
mv ./lokeys "$HOME/.local/bin/lokeys"
chmod 0755 "$HOME/.local/bin/lokeys"
```

Verify:

```bash
lokeys version
lokeys help
```

## Command summary

- `lokeys add <path>`: protect a file and replace original with symlink to RAM copy
- `lokeys remove <path>`: unprotect a file
- `lokeys list`: show tracked files and integrity status
- `lokeys seal`: encrypt current RAM-disk copies to secure storage
- `lokeys unseal`: decrypt tracked files back into RAM disk
- `lokeys backup`: create backup tarball in secure storage
- `lokeys restore [archive.tar.gz]`: restore config + secure data from backup
- `lokeys rotate`: rotate local encryption passphrase/key
- `lokeys enable-kms [--apply]`: dry-run or bootstrap KMS config
- `lokeys kms-rotate --target-key-id <alias-or-arn>`: re-wrap KMS-managed files to a new CMK
- `lokeys session-export`: export `LOKEYS_SESSION_KEY` for current shell

Use global verbose logs:

```bash
lokeys --verbose unseal
```

## Key handling basics

- `lokeys` does not store your local encryption key in config.
- If `LOKEYS_SESSION_KEY` is set, commands use it.
- Otherwise, commands prompt securely for passphrase input.
- KMS is optional. If not configured, lokeys works with local key only.
- If KMS is configured, non-bypassed files fail closed when KMS cannot be used.

Tip: load your local key once per shell session to avoid repeated prompts:

```bash
eval "$(lokeys session-export)"
```

---

## Stories Without AWS KMS (Default)

These workflows use lokeys' default mode: local encryption key + RAM disk, with
no AWS KMS dependency.

### Story 1: Start without KMS and protect `~/.ssh/id_rsa`

**Goal**
- Secure your SSH private key locally using encryption + RAM disk only.

**Steps**

1. Export session key once for this shell (recommended):

```bash
eval "$(lokeys session-export)"
```

2. Initialize lokeys state:

```bash
lokeys list
```

3. Protect your SSH key:

```bash
lokeys add ~/.ssh/id_rsa
```

4. Verify status:

```bash
lokeys list
```

**What lokeys does in the background**
- creates or updates `~/.config/lokeys`
- copies plaintext key into RAM disk (`~/.lokeys/insecure/.ssh/id_rsa`)
- encrypts secure copy at `~/.lokeys/secure/.ssh/id_rsa`
- replaces `~/.ssh/id_rsa` with a symlink to the RAM-disk copy

---

### Story 2: Understand `lokeys list`

**Goal**
- Confirm protection state and detect drift.

Run:

```bash
lokeys list
```

You will see tracked files with hashes and status.

Status meanings:

- `OK`: decrypted RAM copy matches encrypted secure copy
- `MISSING_INSECURE`: RAM copy is missing (often after reboot)
- `MISSING_SECURE`: encrypted copy is missing
- `MISMATCH`: hashes differ (RAM and secure content diverged)
- `UNTRACKED_INSECURE`: file exists in RAM disk but is not yet in config

---

### Story 3: Edit a protected file and save changes

**Goal**
- Safely modify a protected file and persist the update to encrypted storage.

**Steps**

1. Ensure decrypted working set exists:

```bash
lokeys unseal
```

2. Edit file as usual (example):

```bash
nano ~/.ssh/id_rsa
```

3. Save encrypted state:

```bash
lokeys seal
```

4. Confirm:

```bash
lokeys list
```

**What lokeys does in the background**
- `unseal` decrypts secure files into RAM disk and restores symlinks
- your editor writes to RAM-backed plaintext
- `seal` re-encrypts RAM contents into `~/.lokeys/secure`

---

### Story 4: Back up encrypted contents

**Goal**
- Create a portable backup of secure encrypted data + config.

**Steps**

1. Optional but recommended before backup:

```bash
lokeys seal
```

2. Create backup:

```bash
lokeys backup
```

3. Check created archive in secure dir:

```bash
ls -1 ~/.lokeys/secure/*.tar.gz
```

**What lokeys does in the background**
- creates timestamped `.tar.gz` archive under `~/.lokeys/secure`
- includes encrypted secure files and `.config/lokeys` metadata

---

### Story 5: Rotate only the local key (no KMS changes)

**Goal**
- Re-encrypt protected files with a new local passphrase-derived key.

**Steps**

```bash
lokeys rotate
```

You will be asked for old and new passphrases (unless old key is preloaded in
`LOKEYS_SESSION_KEY`).

How `rotate` chooses key input:

- if `LOKEYS_SESSION_KEY` is set, lokeys uses it as the current/previous key
  (no old-key prompt)
- if `LOKEYS_SESSION_KEY` is not set, lokeys prompts for the current/previous key
- in both cases, lokeys always prompts for a new key

**What lokeys does in the background**
- syncs latest RAM content to secure storage
- creates backup snapshot first
- verifies each rotated temp file decrypts with the new key before replace
- KMS CMK setting is unchanged

---

### Story 6: Rotate local key using a manually exported session key

**Goal**
- Avoid old-key prompt during rotation by preloading key in your shell.

**Steps**

1. Export session key:

```bash
eval "$(lokeys session-export)"
```

2. Rotate:

```bash
lokeys rotate
```

3. Optionally clear shell key:

```bash
unset LOKEYS_SESSION_KEY
```

**What lokeys does in the background**
- uses `LOKEYS_SESSION_KEY` as old key source
- skips old-key prompt when env var is present
- always prompts for and validates a different new key

---

### Story 7: Restore on a new machine

**Goal**
- Move encrypted lokeys state and config to another machine and recover working set.

**Steps**

1. Copy backup archive to new machine under `~/.lokeys/secure/` (or keep path handy).

2. Restore from latest archive in secure dir:

```bash
lokeys restore
```

Or restore a specific archive path:

```bash
lokeys restore /path/to/1700000000.tar.gz
```

3. Recreate RAM-disk plaintext working set:

```bash
lokeys unseal
```

4. Verify:

```bash
lokeys list
```

**What lokeys does in the background**
- restores encrypted files to `~/.lokeys/secure`
- restores config to `~/.config/lokeys`
- mounts RAM disk and then `unseal` reconstructs decrypted symlinked working files

---

## Stories With AWS KMS (Optional)

These workflows apply only after KMS is explicitly enabled. They add a KMS CMK
envelope layer for non-bypassed files.

When you enable KMS, lokeys saves both the AWS profile and region used for KMS
access into config. On KMS access errors, lokeys includes both profile and
region in the error.

### Story 1: Enable KMS and protect `~/.aws/credentials` and `~/.ssh/id_rsa`

Assumption: your AWS CLI is already working and authenticated.

**Goal**
- Use KMS CMK envelope protection for regular files while safely bypassing KMS
  for AWS credential files that can create auth dependency loops.

**Steps**

1. Export session key once for this shell (recommended):

```bash
eval "$(lokeys session-export)"
```

2. Validate/preview KMS setup:

```bash
lokeys enable-kms
```

3. Apply KMS setup:

```bash
lokeys enable-kms --apply
```

If you need a specific AWS profile:

```bash
lokeys enable-kms --profile default --apply
```

4. Protect AWS credentials with explicit per-file bypass:

```bash
lokeys add --allow-kms-bypass ~/.aws/credentials
```

5. Protect SSH key with KMS envelope enabled:

```bash
lokeys add ~/.ssh/id_rsa
```

6. Verify:

```bash
lokeys list
```

**What lokeys does in the background**
- configures `kms` in `~/.config/lokeys`
- encrypts `~/.aws/credentials` with local key only (explicit bypass)
- encrypts `~/.ssh/id_rsa` with local key + KMS envelope
- fails closed if KMS is required but unavailable

---

### Story 2: Use `list` in KMS mode and understand output

**Goal**
- Verify file integrity and quickly identify missing/deviated state in KMS mode.

Run:

```bash
lokeys list
```

Statuses are the same (`OK`, `MISSING_INSECURE`, `MISSING_SECURE`, `MISMATCH`,
`UNTRACKED_INSECURE`), but for KMS-managed files lokeys must also be able to
decrypt the KMS envelope.

---

### Story 3: Rotate KMS CMK (`kms-rotate`)

**Goal**
- Keep local key the same, but re-wrap KMS-managed encrypted files to a new CMK.

**Steps**

1. Choose target key (alias or ARN), then run:

```bash
lokeys kms-rotate --target-key-id alias/lokeys-next
```

2. If needed, set explicit region:

```bash
lokeys kms-rotate --target-key-id arn:aws:kms:us-east-1:123456789012:key/abcd-1234 --region us-east-1
```

If needed, also pin profile for the rotation call:

```bash
lokeys kms-rotate --target-key-id alias/lokeys-next --profile default
```

**What lokeys does in the background**
- validates target CMK can generate data keys
- creates backup snapshot first
- re-wraps only KMS-managed files (skips bypassed files like `~/.aws/credentials`)
- updates KMS key config after successful rotation

---

### Story 4: Restore on a new machine with working AWS credentials

Assumption: new machine has working AWS CLI credentials (for KMS-backed files).

**Goal**
- Move encrypted lokeys state and config to another machine and recover working set.

**Steps**

1. Copy backup archive to new machine under `~/.lokeys/secure/` (or keep path handy).

2. Restore from latest archive in secure dir:

```bash
lokeys restore
```

Or restore a specific archive path:

```bash
lokeys restore /path/to/1700000000.tar.gz
```

3. Recreate RAM-disk plaintext working set:

```bash
lokeys unseal
```

4. Verify:

```bash
lokeys list
```

**What lokeys does in the background**
- restores encrypted files to `~/.lokeys/secure`
- restores config to `~/.config/lokeys`
- mounts RAM disk and then `unseal` reconstructs decrypted symlinked working files
- uses AWS credentials to access KMS for KMS-managed files during decrypt

---

## Notes on `~/.aws/*` with KMS

When KMS mode is enabled, `~/.aws/*` files are blocked by default because they
can be required to authenticate KMS calls.

- single-file add bypass:

```bash
lokeys add --allow-kms-bypass ~/.aws/credentials
```

- discovered-file seal bypass (repeat per file):

```bash
lokeys seal --allow-kms-bypass-file '$HOME/.aws/config'
```

Bypass is file-scoped, explicit, and does not apply to other files.

## Integration workflow tests

Integration workflow tests run complete user stories in isolated temporary
directories. They intentionally run through real command orchestration, including
sudo mount prompts and (for KMS mode) AWS credentials from a profile.

### Local workflow group

Runs end-to-end local-key scenarios:

- generate test files
- protect/edit/seal/verify consistency
- simulate reboot by clearing insecure path then unseal and verify symlinks
- rotate local key and re-verify seal/unseal
- backup, wipe state, restore, and verify again

Run:

```bash
make integration-workflows-local
```

### KMS workflow group

Runs the same lifecycle with AWS KMS enabled, plus explicit `.aws/*` bypass
validation.

Required environment:

- `AWS_PROFILE` (required)
- `AWS_REGION` (optional)
- `KMS_ALIAS` (optional, default `alias/lokeys-itest`)

Run:

```bash
make integration-workflows-kms AWS_PROFILE=default
```

### Run both groups

```bash
make integration-workflows AWS_PROFILE=default
```

### Path isolation and overrides

Integration scripts set all lokeys path overrides to temporary locations:

- `LOKEYS_HOME`
- `LOKEYS_CONFIG_PATH`
- `LOKEYS_SECURE_DIR`
- `LOKEYS_INSECURE_DIR`

This keeps tests isolated from your real home directory and config.

## Troubleshooting

- Wrong key in environment:
  - `unset LOKEYS_SESSION_KEY`
- RAM-disk mount issue:
  - `sudo umount "$HOME/.lokeys/insecure"` then rerun
- Need detailed diagnostics:
  - run with `--verbose`
