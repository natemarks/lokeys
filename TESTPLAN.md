# lokeys Manual Test Plan

This test plan covers manual verification of `lokeys` command behavior, organized by normal workflows first and edge cases second.

## Test Environment

- OS: Linux with `tmpfs` support
- User has `sudo` rights for mount/umount
- `lokeys` available as either:
  - built binary: `./lokeys`
  - or via Go: `go run ./cmd/lokeys`

In examples below, use this helper so commands are consistent:

```bash
LOKEYS="go run ./cmd/lokeys"
# or: LOKEYS="./lokeys"
```

Use an isolated fixture area:

```bash
TEST_ROOT="$HOME/lokeys-manual-test"
mkdir -p "$TEST_ROOT"
```

## Main Workflows

### 1) Basic command discovery and help

Goal: Verify top-level CLI usability.

Steps:

1. Run: `$LOKEYS help`
2. Run: `$LOKEYS commands`
3. Run: `$LOKEYS version`

Expected:

- Help text lists: `list`, `add`, `remove`, `seal`, `unseal`, `backup`, `session-export`, `version`
- Help text includes session key guidance
- `version` prints a version string and exits `0`

### 2) First-time initialization (`list`)

Goal: Verify initial state creation.

Steps:

1. Ensure clean state:

   ```bash
   sudo umount "$HOME/.lokeys/insecure" 2>/dev/null || true
   rm -f "$HOME/.config/lokeys"
   rm -rf "$HOME/.lokeys"
   ```

2. Run: `$LOKEYS list`

Expected:

- Command creates:
  - `~/.config/lokeys`
  - `~/.lokeys/secure`
  - `~/.lokeys/insecure`
- `~/.config/lokeys` has mode `0600`
- lokeys directories have mode `0700`
- RAM disk is mounted at `~/.lokeys/insecure`
- Command exits `0`

### 3) Add + list + symlink verification

Goal: Verify file protection flow.

Steps:

1. Create source file:

   ```bash
   mkdir -p "$TEST_ROOT/secrets"
   printf 'api-token-123\n' > "$TEST_ROOT/secrets/demo.txt"
   chmod 0600 "$TEST_ROOT/secrets/demo.txt"
   ```

2. Run: `$LOKEYS add "$TEST_ROOT/secrets/demo.txt"`
3. Run: `$LOKEYS list`
4. Inspect path:

   ```bash
   ls -l "$TEST_ROOT/secrets/demo.txt"
   ```

Expected:

- `add` prompts for encryption key (if `LOKEYS_SESSION_KEY` is unset)
- Original file becomes a symlink to `~/.lokeys/insecure/...`
- Encrypted copy exists under `~/.lokeys/secure/...`
- `list` prints entry with `OK`

### 4) Seal/unseal round trip after edit

Goal: Verify secure persistence and RAM restore.

Steps:

1. Edit through the symlink path:

   ```bash
   printf 'api-token-456\n' > "$TEST_ROOT/secrets/demo.txt"
   ```

2. Run: `$LOKEYS list` (capture status)
3. Run: `$LOKEYS seal`
4. Simulate RAM loss:

   ```bash
   sudo umount "$HOME/.lokeys/insecure"
   ```

5. Run: `$LOKEYS unseal`
6. Run: `cat "$TEST_ROOT/secrets/demo.txt"`
7. Run: `$LOKEYS list`

Expected:

- Before `seal`, `list` may show `MISMATCH` when plaintext changed and encrypted copy is stale
- `seal` succeeds and updates encrypted file
- After unmount, `unseal` remounts RAM disk and restores decrypted copies
- File content equals `api-token-456`
- Final `list` status is `OK`

### 5) Backup workflow (`backup`)

Goal: Verify tar backup generation and content.

Steps:

1. Run: `$LOKEYS backup`
2. Identify produced tar in `~/.lokeys/secure/*.tar`
3. Inspect tar:

   ```bash
   tar -tf "<backup-tar-path>"
   ```

Expected:

- Command prints `backup created: <path>`
- Tar exists with mode `0600`
- Tar includes encrypted storage content and `.config/lokeys`
- Tar does not include itself recursively

### 6) Session key workflow (`session-export`)

Goal: Verify non-reprompt flow with environment key.

Steps:

1. Run: `eval "$($LOKEYS session-export)"`
2. Verify var set:

   ```bash
   [ -n "$LOKEYS_SESSION_KEY" ] && echo "set"
   ```

3. Run multiple commands (`list`, `seal`, `unseal`) in same shell

Expected:

- Session export prints a valid `export LOKEYS_SESSION_KEY='...'` line
- Subsequent commands do not prompt for key in that shell
- Commands complete successfully using env key

### 7) Remove workflow (`remove`)

Goal: Verify unprotect and cleanup behavior.

Steps:

1. Run: `$LOKEYS remove "$TEST_ROOT/secrets/demo.txt"`
2. Check file is no longer symlink:

   ```bash
   test -L "$TEST_ROOT/secrets/demo.txt" && echo "still symlink" || echo "regular"
   ```

3. Run: `$LOKEYS list`

Expected:

- Command prints `removed protection for $HOME/...`
- Original path becomes a regular file with latest plaintext
- Managed secure/insecure copies for that file are removed
- File is no longer listed as protected

## Edge Cases

### 1) Usage errors and exit codes

Goal: Verify argument validation and usage exit status.

Steps:

```bash
$LOKEYS add
echo $?
$LOKEYS list extra
echo $?
$LOKEYS version extra
echo $?
```

Expected:

- Each command prints a usage error message
- Exit code is `2` for usage errors

### 2) Reject paths outside `$HOME`

Goal: Verify path safety guard.

Steps:

```bash
sudo sh -c "printf 'x\n' > /tmp/lokeys-outside-home.txt"
$LOKEYS add /tmp/lokeys-outside-home.txt
echo $?
```

Expected:

- Command fails with message equivalent to `path must be under $HOME`
- Exit code is non-zero

### 3) Reject symlink and non-regular file for `add`

Goal: Verify `add` input validation.

Steps:

```bash
mkdir -p "$TEST_ROOT/edge"
printf 'real\n' > "$TEST_ROOT/edge/real.txt"
ln -sf "$TEST_ROOT/edge/real.txt" "$TEST_ROOT/edge/link.txt"
mkfifo "$TEST_ROOT/edge/fifo"

$LOKEYS add "$TEST_ROOT/edge/link.txt"
$LOKEYS add "$TEST_ROOT/edge/fifo"
```

Expected:

- Symlink add fails with `path is a symlink`
- FIFO add fails with `path is not a regular file`

### 4) Wrong session key in environment

Goal: Verify key validation and actionable failure.

Steps:

1. Protect at least one file successfully first
2. Set bogus key:

   ```bash
   export LOKEYS_SESSION_KEY='not-base64'
   $LOKEYS list
   echo $?
   ```

Expected:

- Command fails with encoded key parsing error
- Exit code is non-zero
- Recovery: `unset LOKEYS_SESSION_KEY`, then rerun with prompt

### 5) Non-interactive shell without session key

Goal: Verify behavior when prompting is impossible.

Steps:

```bash
unset LOKEYS_SESSION_KEY
printf '' | $LOKEYS list
echo $?
```

Expected:

- Command fails with `encryption key required: run in a terminal` (or sudo terminal requirement if mount is needed)
- Exit code is non-zero

### 6) Missing secure or insecure copies (`list` statuses)

Goal: Verify integrity status reporting.

Steps:

1. Protect a file and ensure baseline `OK`
2. Delete insecure copy only, run `list`
3. Restore via `unseal`, then delete secure copy only, run `list`
4. Modify insecure plaintext without sealing, run `list`

Expected:

- Status transitions match:
  - insecure missing -> `MISSING_INSECURE`
  - secure missing -> `MISSING_SECURE`
  - hash mismatch -> `MISMATCH`

### 7) `remove` when target is not protected

Goal: Verify idempotent and friendly behavior.

Steps:

```bash
printf 'noop\n' > "$TEST_ROOT/not-protected.txt"
$LOKEYS remove "$TEST_ROOT/not-protected.txt"
echo $?
```

Expected:

- Prints `<path> is not protected.`
- Exits `0`

### 8) Mount exists but not writable by current user

Goal: Verify mount ownership diagnostic.

Steps:

1. Arrange for `~/.lokeys/insecure` to be mounted by root with incompatible ownership/mode
2. Run a command that ensures mount (`list`, `add`, `seal`, or `unseal`)

Expected:

- Command fails with guidance to unmount and retry:
  - `ramdisk mounted at ... is not writable by the current user; unmount and retry: sudo umount ...`

## Cleanup

```bash
unset LOKEYS_SESSION_KEY
sudo umount "$HOME/.lokeys/insecure" 2>/dev/null || true
rm -f "$HOME/.config/lokeys"
rm -rf "$HOME/.lokeys" "$TEST_ROOT"
```
