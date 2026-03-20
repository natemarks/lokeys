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

- Help text lists: `list`, `add`, `remove`, `seal`, `unseal`, `backup`, `rotate`, `session-export`, `version`
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

1. Create an untracked RAM-disk file:

   ```bash
   mkdir -p "$HOME/.lokeys/insecure/backup-new"
   printf 'backup-data\n' > "$HOME/.lokeys/insecure/backup-new/note.txt"
   ```

2. Run: `$LOKEYS backup`
3. Identify produced archive in `~/.lokeys/secure/*.tar.gz`
4. Inspect tar:

   ```bash
   tar -tzf "<backup-tar-gz-path>"
   ```

Expected:

- Command prints `backup created: <path>`
- Tar exists with mode `0600`
- Tar includes encrypted storage content and `.config/lokeys`
- External RAM-disk files are enrolled/protected before backup (secure copy + config entry)
- Tar does not include itself recursively

### 5d) Rotate key (`rotate`) with RAM changes preserved

Goal: Verify key rotation uses RAM plaintext, creates pre-rotation backup, and validates new key output.

Steps:

1. Protect a file first (from earlier workflow), then edit through symlink path without sealing:

   ```bash
   printf 'rotated-from-ram\n' > "$TEST_ROOT/secrets/demo.txt"
   ```

2. Ensure old key is available (either export or be ready to type prompt):

   ```bash
   eval "$($LOKEYS session-export)"
   ```

3. Run: `$LOKEYS rotate`
4. Confirm a new `~/.lokeys/secure/*.tar.gz` backup was created during rotation.
5. Unset old key material and set new key from `session-export` prompt flow.
6. Simulate RAM loss and restore:

   ```bash
   sudo umount "$HOME/.lokeys/insecure"
   $LOKEYS unseal
   cat "$TEST_ROOT/secrets/demo.txt"
   ```

Expected:

- `rotate` succeeds and reports backup path plus rotated count
- Pre-rotation backup archive exists as `.tar.gz`
- External RAM-disk files are enrolled before rotation and included in rotated count
- `unseal` with new key restores latest RAM-edited content (`rotated-from-ram`)
- Old key no longer decrypts rotated ciphertext

### 5b) Protect files created directly on RAM disk with `add`

Goal: Verify `add` supports files created inside `~/.lokeys/insecure`.

Steps:

1. Create a new file directly on RAM disk:

   ```bash
   mkdir -p "$HOME/.lokeys/insecure/ram-created/demo"
   printf 'ram-origin\n' > "$HOME/.lokeys/insecure/ram-created/demo/from-ram.txt"
   ```

2. Run:

   ```bash
   $LOKEYS add "$HOME/.lokeys/insecure/ram-created/demo/from-ram.txt"
   ```

3. Inspect derived home path:

   ```bash
   ls -l "$HOME/ram-created/demo/from-ram.txt"
   ```

4. Run: `$LOKEYS list`

Expected:

- `add` succeeds
- `$HOME/ram-created/demo/from-ram.txt` is created as a symlink to `~/.lokeys/insecure/ram-created/demo/from-ram.txt`
- Encrypted copy exists at `~/.lokeys/secure/ram-created/demo/from-ram.txt`
- `list` includes `$HOME/ram-created/demo/from-ram.txt` with `OK`

### 5c) Auto-protect new RAM files during `seal`

Goal: Verify `seal` discovers and protects untracked RAM-disk files.

Steps:

1. Create a new untracked RAM-disk file:

   ```bash
   mkdir -p "$HOME/.lokeys/insecure/auto-seal"
   printf 'auto-seal-value\n' > "$HOME/.lokeys/insecure/auto-seal/new.txt"
   ```

2. Run: `$LOKEYS seal`
3. Verify derived home path:

   ```bash
   ls -l "$HOME/auto-seal/new.txt"
   ```

4. Run: `$LOKEYS list`

Expected:

- `seal` succeeds
- New file is enrolled as protected using relative path `auto-seal/new.txt`
- `$HOME/auto-seal/new.txt` exists as symlink to RAM copy
- Encrypted copy exists at `~/.lokeys/secure/auto-seal/new.txt`
- `list` includes `$HOME/auto-seal/new.txt` with `OK`

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

### 9) Conflict detection for RAM-origin files (`add` and `seal`)

Goal: Verify conflict guard against existing derived home path.

Steps (`add` conflict):

```bash
mkdir -p "$HOME/.lokeys/insecure/conflict-test"
printf 'from-ram\n' > "$HOME/.lokeys/insecure/conflict-test/add.txt"
mkdir -p "$HOME/conflict-test"
printf 'already-here\n' > "$HOME/conflict-test/add.txt"
$LOKEYS add "$HOME/.lokeys/insecure/conflict-test/add.txt"
echo $?
```

Expected (`add`):

- Command fails because derived `$HOME/conflict-test/add.txt` already exists
- Exit code is non-zero

Steps (`seal` fail-fast):

```bash
mkdir -p "$HOME/.lokeys/insecure/conflict-seal/a"
mkdir -p "$HOME/.lokeys/insecure/conflict-seal/b"
printf 'conflict\n' > "$HOME/.lokeys/insecure/conflict-seal/a/file.txt"
printf 'safe\n' > "$HOME/.lokeys/insecure/conflict-seal/b/file.txt"
mkdir -p "$HOME/conflict-seal/a"
printf 'already-here\n' > "$HOME/conflict-seal/a/file.txt"
$LOKEYS seal
echo $?
```

Expected (`seal`):

- `seal` fails immediately on first conflict (`$HOME/conflict-seal/a/file.txt` exists)
- Exit code is non-zero
- No new protected entry is added for the non-conflicting file in `conflict-seal/b/file.txt`

### 10) `list` reports externally created RAM-disk files

Goal: Verify list surfaces untracked insecure files without mutating config.

Steps:

```bash
mkdir -p "$HOME/.lokeys/insecure/external"
printf 'external\n' > "$HOME/.lokeys/insecure/external/new.txt"
$LOKEYS list
```

Expected:

- Output includes `$HOME/external/new.txt`
- Status includes `UNTRACKED_INSECURE`
- Config is not modified by `list`

### 11) Restore on a new machine (`restore`)

Goal: Verify restoring from copied `~/.lokeys/secure` recreates config and
secure content without auto-unseal.

Steps:

1. Copy a secure directory containing one or more `*.tar.gz` backups to a new machine.
2. Ensure `~/.config/lokeys` and `~/.lokeys/insecure` are absent.
3. Run `lokeys restore` (defaults to latest archive) or `lokeys restore <archive.tar.gz>`.

Expected:

- Restore selects latest archive when no argument is provided.
- Restore recreates `~/.config/lokeys` from archive content.
- Restore writes encrypted files back to `~/.lokeys/secure`.
- Restore ensures RAM-disk mount path exists, but does not auto-unseal files.

### 12) AWS default credential files auto-bypass KMS

Goal: Verify `~/.aws/config` and `~/.aws/credentials` bypass KMS automatically
when KMS mode is enabled.

Steps:

1. Enable KMS:

   ```bash
   $LOKEYS enable-kms --apply
   ```

2. Create AWS default files:

   ```bash
   mkdir -p "$HOME/.aws"
   printf '[default]\nregion=us-east-1\n' > "$HOME/.aws/config"
   printf '[default]\naws_access_key_id=AKIAFAKE\naws_secret_access_key=FAKE\n' > "$HOME/.aws/credentials"
   ```

3. Add both files without bypass flags:

   ```bash
   $LOKEYS add "$HOME/.aws/config"
   $LOKEYS add "$HOME/.aws/credentials"
   ```

4. Seal + unseal:

   ```bash
   $LOKEYS seal
   sudo umount "$HOME/.lokeys/insecure"
   $LOKEYS unseal
   ```

Expected:

- Both `add` commands succeed without `--allow-kms-bypass`
- `seal` succeeds without `--allow-kms-bypass-file`
- `unseal` succeeds even when KMS is unavailable, as long as only default AWS
  files are protected

### 13) Non-default `~/.aws/*` files still require explicit bypass

Goal: Verify fail-closed behavior remains for non-default AWS paths.

Steps:

```bash
mkdir -p "$HOME/.aws/sso/cache"
printf '{"accessToken":"test"}\n' > "$HOME/.aws/sso/cache/token.json"
$LOKEYS add "$HOME/.aws/sso/cache/token.json"
echo $?
$LOKEYS add --allow-kms-bypass "$HOME/.aws/sso/cache/token.json"
```

Expected:

- First add fails with dependency-loop / explicit bypass guidance
- Second add succeeds with explicit bypass flag

## Automated Test Coverage (New)

The codebase now includes expanded automated tests focused on isolated,
readable validation of core logic and command wiring.

### Module map and intent

- `internal/lokeys/tracked_file_test.go`
  - Covers canonical path mapping between `$HOME`, RAM-disk, and encrypted
    storage roots.
  - Verifies RAM-origin detection and outside-home rejection behavior.
- `internal/lokeys/crypto_test.go`
  - Covers v2 round-trip encryption/decryption, legacy v1 compatibility,
    deterministic encryption fixture support (`encryptBytesWithRand`), and
    malformed header/nonce error handling.
- `internal/lokeys/fs_backup_test.go`
  - Covers backup archive structure and deterministic timestamp naming via
    `createBackupTarGzWithNow`.
- `internal/lokeys/operations_test.go`
  - Covers add/seal command orchestration through `Service` methods with temp
    HOME fixtures and injected mount/key boundaries.
  - Verifies conflict fail-fast behavior, AWS auto-bypass behavior for default
    credential files, and no partial state mutation.
- `internal/lokeys/kms_policy_test.go`
  - Covers KMS policy selection for AWS auto-bypass defaults versus non-default
    `.aws/*` paths.
- `internal/lokeys/list_operation_test.go`
  - Covers list reporting for externally created untracked RAM-disk files.
- `internal/lokeys/backup_operation_test.go`
  - Covers backup command pre-backup enrollment of untracked RAM-disk files.
- `internal/lokeys/restore_operation_test.go`
  - Covers restore default/latest archive selection, explicit archive usage,
    mount ensure behavior, and safe extraction checks.
- `internal/lokeys/add_plan_test.go`, `internal/lokeys/seal_plan_test.go`,
  `internal/lokeys/unseal_plan_test.go`, `internal/lokeys/remove_plan_test.go`
  - Covers explicit planner output for core mutating flows.
  - Verifies action ordering and whether config writes are planned only when
    required.
- `internal/lokeys/executor_test.go`
  - Covers explicit plan executor behavior.
  - Verifies ordered action application and stop-on-first-failure semantics.
- `internal/lokeys/rotate_test.go`
  - Covers key rotation semantics through injected prompt/mount dependencies,
  including RAM-preferred plaintext, backup creation, prompt fallback,
  same-key rejection, and discovered-file enrollment before rotation.
- `internal/lokeys/key_test.go`
  - Covers session env decoding errors and wrong-key validation behavior for
    existing encrypted files.
- `internal/lokeys/config_test.go`
  - Covers atomic config replacement behavior (`write temp + rename`) and
    resulting file mode expectations.
- `internal/lokeys/ramdisk_test.go`
  - Covers mount parsing helper behavior and non-interactive mount prompt
    failure safeguards.
- `internal/lokeys/service_test.go`
  - Covers dependency defaulting for `Service` construction and verifies
    interface-based adapters (`RamdiskMounter`, `KeySource`) are used by
    command methods.
- `internal/lokeys/session_key_test.go`
  - Covers fail-fast command behavior with malformed session key env values.
- `internal/lokeys/test_helpers_test.go`
  - Provides shared test service/key fixtures used by operation/rotation tests
    to keep test modules concise and consistent.
- `cmd/lokeys/main_test.go`
  - Covers CLI argument validators and error-to-exit-code mapping (`0/1/2`).

### Function-level test index (purpose + function)

- `internal/lokeys/tracked_file_test.go`
  - `TestBuildTrackedFileFromPortable_ValidHomePath`: verifies portable path expansion and canonical path derivation.
  - `TestBuildTrackedFileFromPortable_RejectsOutsideHome`: verifies outside-home rejection guard.
  - `TestBuildTrackedFileFromInsecurePath_DetectsRamdiskOrigin`: verifies RAM-origin detection and derived home/portable mapping.
  - `TestBuildTrackedFileFromInsecurePath_NonRamdiskReturnsFalse`: verifies non-RAM inputs return a clean false signal.
  - `TestBuildTrackedFileFromHomePath_ComputesSecureAndInsecurePaths`: verifies canonical path mapping from home input.
- `internal/lokeys/crypto_test.go`
  - `TestEncryptDecryptV2RoundTrip`: verifies v2 ciphertext round-trip correctness.
  - `TestDecryptBytesSupportsLegacyV1Format`: verifies backward compatibility with v1 payloads.
  - `TestEncryptBytesWithRand_DeterministicHeaderAndNonceForFixtureReader`: verifies deterministic fixture generation with injected randomness.
  - `TestDecryptBytesV2_InvalidNonceLen_Errors`: verifies malformed nonce metadata rejection.
  - `TestDecryptBytesV2_UnsupportedKDFID_Errors`: verifies unsupported KDF identifiers are rejected.
- `internal/lokeys/fs_backup_test.go`
  - `TestCreateBackupTarGzCreatesCompressedArchive`: verifies archive creation and expected content entries.
  - `TestCreateBackupTarGzWithNow_UsesDeterministicTimestampName`: verifies deterministic backup name generation with injected clock.
- `internal/lokeys/operations_test.go`
  - `TestRunAddProtectsRamdiskCreatedFile`: verifies RAM-origin add flow creates symlink, ciphertext, and config enrollment.
  - `TestRunAddFailsWhenDerivedHomePathExists`: verifies add conflict guard on derived home path collisions.
  - `TestRunSealDiscoversAndProtectsRamdiskFiles`: verifies seal discovery enrolls untracked RAM files.
  - `TestRunSealFailsFastOnFirstConflict`: verifies seal aborts on first conflict without partial enrollment.
  - `TestRunAdd_AWSCredentialsAutoBypassWithoutFlag`: verifies default AWS credentials path bypasses KMS automatically.
  - `TestRunAdd_AWSNonDefaultPathStillRequiresExplicitBypass`: verifies non-default AWS paths stay fail-closed unless explicitly bypassed.
  - `TestRunSeal_AWSDefaultsDiscoveryAutoBypass`: verifies seal discovery auto-bypasses default AWS config/credentials.
  - `TestRunSeal_AWSNonDefaultDiscoveryStillNeedsExplicitBypass`: verifies non-default discovered AWS paths require explicit bypass.
  - `TestRunUnseal_AWSDefaultsDoNotRequireKMSHealthCheck`: verifies unseal does not require KMS readiness for default AWS auto-bypass files.
- `internal/lokeys/kms_policy_test.go`
  - `TestShouldUseKMSForPortable_AWSDefaultsAutoBypass`: verifies policy auto-bypasses only default AWS config/credentials paths.
  - `TestShouldUseKMSForPortable_NonDefaultAWSPathStillRequiresBypass`: verifies non-default AWS paths still default to KMS.
- `internal/lokeys/list_operation_test.go`
  - `TestRunList_ShowsExternallyCreatedInsecureFileAsUntracked`: verifies list reports untracked insecure files with `UNTRACKED_INSECURE` status.
- `internal/lokeys/backup_operation_test.go`
  - `TestRunBackup_EnrollsUntrackedInsecureFilesBeforeArchive`: verifies backup enrolls external RAM files before tar creation.
- `internal/lokeys/restore_operation_test.go`
  - `TestRunRestore_DefaultsToLatestArchive`: verifies restore selects newest archive when none is specified.
  - `TestRunRestore_UsesSpecifiedArchive`: verifies restore honors explicit archive selection.
  - `TestRestoreFromArchive_RejectsPathTraversal`: verifies restore extraction rejects traversal entries.
- `internal/lokeys/add_plan_test.go`
  - `TestPlanAdd_NewHomeFile_ContainsExpectedActions`: verifies add planner action chain for non-RAM sources.
  - `TestPlanAdd_RamdiskSource_SkipsCopyAction`: verifies RAM-origin add planning skips redundant copy.
- `internal/lokeys/seal_plan_test.go`
  - `TestPlanSeal_WithDiscoveredFiles_AppendsConfigWrite`: verifies discovered-file enrollment plans a config write.
  - `TestPlanSeal_NoDiscoveredFiles_SkipsConfigWrite`: verifies no config write is planned when nothing new is enrolled.
- `internal/lokeys/unseal_plan_test.go`
  - `TestPlanUnseal_DecryptAndSymlinkActions`: verifies unseal planner emits ensure-parent, decrypt, and symlink actions in order.
- `internal/lokeys/remove_plan_test.go`
  - `TestPlanRemove_ManagedSymlink_RestoreAndCleanupActions`: verifies remove planner emits restore, cleanup, and config update actions.
- `internal/lokeys/executor_test.go`
  - `TestApplyPlan_ExecutesActionsInOrder`: verifies sequential action execution on successful plans.
  - `TestApplyPlan_StopsOnFirstFailure`: verifies executor halts and does not apply trailing actions after error.
- `internal/lokeys/rotate_test.go`
  - `TestRunRotateUsesRamdiskContentAndCreatesTarGzBackup`: verifies rotate uses freshest RAM plaintext and writes backup.
  - `TestRunRotatePromptsOldKeyWhenEnvMissing`: verifies rotate falls back to prompt path when env key is absent.
  - `TestRunRotateRejectsSameOldAndNewKey`: verifies rotate rejects no-op key changes.
  - `TestRunRotate_EnrollsAndRotatesDiscoveredInsecureFiles`: verifies rotate enrolls discovered RAM files and rotates them under the new key.
- `internal/lokeys/key_test.go`
  - `TestKeyFromSessionEnv_InvalidBase64_ErrorsWithEnvName`: verifies malformed session-key env parse errors include env context.
  - `TestKeyFromSessionEnv_InvalidLength_Errors`: verifies decoded key length enforcement.
  - `TestValidateKeyForExistingProtectedFiles_WrongKey_Errors`: verifies wrong-key detection against existing secure files.
- `internal/lokeys/config_test.go`
  - `TestWriteConfigTo_ReplacesConfigContents`: verifies atomic config replacement updates data and preserves expected mode.
- `internal/lokeys/ramdisk_test.go`
  - `TestIsMountedInProcMounts_ParsesEntries`: verifies /proc/mounts parser behavior.
  - `TestEnsureRamdiskMounted_NonTerminalPromptRequired_ErrorsActionably`: verifies clear non-interactive error behavior.
- `internal/lokeys/service_test.go`
  - `TestNewService_DefaultsMissingDependencies`: verifies default adapter/writer/clock population.
  - `TestNewService_PreservesProvidedDependencies`: verifies explicit deps are preserved.
  - `TestServiceRunList_UsesInjectedMountAndOutput`: verifies command uses injected mounter and stdout.
  - `TestServiceRunSessionExport_UsesInjectedPrompt`: verifies session-export uses injected key prompt source.
- `internal/lokeys/session_key_test.go`
  - `TestRunListFailsFastWithWrongSessionKey`: verifies malformed env key fails before command progression.
- `cmd/lokeys/main_test.go`
  - `TestRequireNoArgs_ReturnsUsageError`: verifies extra args for no-arg commands map to usage errors.
  - `TestRequireOneArg_ReturnsUsageErrorOnZeroOrMany`: verifies exact-arity enforcement.
  - `TestRequireZeroOrOneArg_ReturnsUsageErrorOnMany`: verifies optional-arg command arity enforcement.
  - `TestRunWithExitStatus_MapsUsageToExitUsageError`: verifies error-to-exit-code mapping (`0/1/2`).

### How to run automated tests

Run all tests:

```bash
go test ./... -count=1
```

Run only internal package tests:

```bash
go test ./internal/lokeys -count=1
```

Run only CLI package tests:

```bash
go test ./cmd/lokeys -count=1
```

## Cleanup

```bash
unset LOKEYS_SESSION_KEY
sudo umount "$HOME/.lokeys/insecure" 2>/dev/null || true
rm -f "$HOME/.config/lokeys"
rm -rf "$HOME/.lokeys" "$TEST_ROOT"
```
