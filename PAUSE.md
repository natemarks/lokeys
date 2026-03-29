# Plan: Add `pause` / `unpause` and paused-file behavior

This document is a step-by-step implementation plan for introducing paused managed files.

## Goals

1. Add `pause` and `unpause` subcommands.
2. Change config format so each managed file carries a `paused` flag.
3. Ensure `unseal` skips paused files.
4. Keep `seal` behavior the same except: do **not** fail if a managed file is missing from RAM disk.
5. Keep `list` behavior, but visibly indicate paused files.
6. Extend unit and integration tests to cover all new behavior.

## Config format change (explicit spec)

### Current (legacy) format

```json
{
  "protectedFiles": [
    "$HOME/docs/a.txt",
    "$HOME/ssh/id_test"
  ],
  "kms": {
    "enabled": true,
    "keyId": "alias/lokeys",
    "region": "us-east-1"
  },
  "kmsBypassFiles": [
    "$HOME/.aws/config",
    "$HOME/.aws/credentials"
  ]
}
```

### New format

```json
{
  "protectedFiles": [
    { "path": "$HOME/docs/a.txt", "paused": false },
    { "path": "$HOME/ssh/id_test", "paused": true }
  ],
  "kms": {
    "enabled": true,
    "keyId": "alias/lokeys",
    "region": "us-east-1"
  },
  "kmsBypassFiles": [
    "$HOME/.aws/config",
    "$HOME/.aws/credentials"
  ]
}
```

### Compatibility and migration rules

1. **Read compatibility is required**:
   - `protectedFiles` as `[]string` must still load successfully.
   - Each legacy string entry maps to `{ "path": "...", "paused": false }`.
2. **Write format should be canonicalized**:
   - Config writes should emit only the new object-entry format.
3. **Behavior default for legacy data**:
   - Legacy entries are treated as **unpaused**.
4. **No change to KMS fields**:
   - `kms` and `kmsBypassFiles` schema remain unchanged.
5. **Path identity remains portable**:
   - `path` continues to use existing portable form (`$HOME/...`).

### Entry semantics

- `path` (string, required): portable managed file path (`$HOME/...`).
- `paused` (bool, optional on read, default `false`):
  - `true` => `unseal` skips this file.
  - `false` => normal behavior.

---

## Step 1: Define the new config shape (with backward compatibility)

1. Introduce a file-entry struct for protected files (example fields: `path`, `paused`).
2. Update internal `config` model from `[]string` to `[]entry`.
3. Add compatibility logic in config loading so old configs like:
   - `"protectedFiles": ["$HOME/a.txt", "$HOME/b.txt"]`
   are accepted and mapped to:
   - `[{"path":"$HOME/a.txt","paused":false}, ...]`
4. Ensure config writes always emit the new object-based format.
5. Preserve existing config permissions and atomic write behavior.

Acceptance check:
- Existing users with old config can run commands without migration failures.

---

## Step 2: Add helper methods for protected-file entries

1. Add internal helpers to avoid repetitive entry-wrangling logic:
   - find by portable path
   - contains path
   - set paused/unpaused
   - remove entry
   - list only paths / list with metadata
2. Use helpers to keep operation code minimal and reduce regressions.

Acceptance check:
- Core operations can access both path and paused state without duplicate loops.

---

## Step 3: Add `pause` and `unpause` commands (CLI wiring)

1. Add `cmd/lokeys/pause_command.go` and `cmd/lokeys/unpause_command.go`.
2. Register commands in `cmd/lokeys/main.go`.
3. Command usage:
   - `pause <path>`
   - `unpause <path>`
4. Reuse existing arg validation pattern (`requireOneArg`).
5. Keep usage error exit code behavior consistent (`ExitUsageError` for bad args).

Acceptance check:
- `lokeys commands` shows both new subcommands.

---

## Step 4: Implement `RunPause` / `RunUnpause` operations

1. Add service methods and operation files for pause/unpause.
2. Normalize user path input to portable `$HOME/...` form, matching existing command conventions.
3. If the path is managed:
   - `pause` sets `paused=true`
   - `unpause` sets `paused=false`
   - persist config
4. If the path is not managed:
   - print a friendly informational message
   - return success (non-fatal)
5. Make both commands idempotent (already paused/unpaused should still succeed).

Acceptance check:
- Pause state toggles only config metadata; no file encryption/decryption side effects.

---

## Step 5: Update `unseal` to skip paused files

1. During tracked-file resolution in `RunUnseal`, split files into:
   - unpaused (eligible for normal unseal)
   - paused (skip)
2. Do not emit decrypt/symlink actions for paused entries.
3. Keep all existing KMS handling for eligible files unchanged.

Acceptance check:
- After clearing insecure dir, unseal restores only unpaused managed files.

---

## Step 6: Update `seal` to tolerate missing managed insecure files

1. In seal planning for managed entries, check whether insecure source exists.
2. If insecure source is missing for a managed file:
   - skip encryption action for that file
   - continue processing other files
3. Preserve discovery behavior for untracked insecure files exactly as today.

Acceptance check:
- `seal` succeeds when one or more managed files are absent from RAM disk.

---

## Step 7: Update `list` to show paused status

1. Keep current status computation (`OK`, `MISSING_INSECURE`, etc.).
2. Add paused indicator for managed entries with `paused=true`.
3. Keep output stable and grep-friendly for scripts.
4. Ensure untracked insecure reporting remains unchanged.

Acceptance check:
- List output clearly distinguishes paused managed files.

---

## Step 8: Extend unit tests

### 8.1 Config tests
1. Add test: legacy string-array config reads successfully with `paused=false` default.
2. Add test: new object format read/write round-trip preserves paused flags.

### 8.2 Pause/unpause tests
1. Add tests for:
   - pause managed file
   - unpause managed file
   - idempotent pause/unpause
   - non-managed target returns success with friendly message

### 8.3 Unseal tests
1. Add test proving paused files are skipped on unseal.
2. Add test proving unpaused files still unseal normally in same run.

### 8.4 Seal tests
1. Add test proving missing managed insecure file does not fail seal.
2. Add test proving other files still seal successfully in same run.

### 8.5 List tests
1. Add test proving paused managed files are annotated in output.
2. Keep existing status assertions intact.

### 8.6 CLI tests
1. Extend command-arg tests for `pause` and `unpause` arity/usage behavior.

Acceptance check:
- New tests fail before implementation changes and pass afterward.

---

## Step 9: Extend integration scripts

### 9.1 `scripts/integration/common.sh`
1. Add helper assertions for paused marker in list output.

### 9.2 `scripts/integration/local_workflow.sh`
1. Protect multiple files as usual.
2. Pause one managed file.
3. Clear insecure dir and run `unseal`.
4. Assert paused file is not restored, unpaused files are restored.
5. Run `list` and assert paused marker is present.
6. Run `seal` while paused file is missing from insecure and assert success.
7. Unpause, run `unseal`, assert file is restored again.

### 9.3 `scripts/integration/kms_workflow.sh`
1. Repeat pause/unpause flow for a KMS-managed file (e.g., docs file).
2. Validate same skip/tolerate/restore behavior under KMS-enabled config.

Acceptance check:
- Integration scripts exercise pause state end-to-end and remain stable.

---

## Step 10: Quality gate and regression check

1. Run full static/test gate (`make static`).
2. Fix any issues (format, lint, vet, unit tests, build).
3. Re-run until fully green.

Acceptance check:
- All static checks pass with pause/unpause changes included.

---

## Step 11: Documentation updates

1. Update user-facing docs/help text to mention:
   - new `pause` and `unpause` commands
   - paused behavior in `unseal`
   - list paused indicator
   - seal tolerance for missing managed insecure files
2. Update manual test plan with pause/unpause scenarios.

Acceptance check:
- Operators can discover and validate the new workflow from docs alone.
