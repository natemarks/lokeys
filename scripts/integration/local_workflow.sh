#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=scripts/integration/common.sh
source "$(dirname "$0")/common.sh"

require_cmd readlink
require_cmd rm
require_tty

create_temp_layout
trap cleanup_layout EXIT
log_layout

# Seed representative plaintext files under HOME. These are the user-facing
# paths that should become symlinks into the RAM-backed insecure directory.
log_step "Initializing local workflow test layout"
mkdir -p "$TEST_HOME/docs" "$TEST_HOME/ssh" "$TEST_HOME/notes"
printf 'alpha\n' >"$TEST_HOME/docs/a.txt"
printf 'bravo\n' >"$TEST_HOME/ssh/id_test"
printf 'charlie\n' >"$TEST_HOME/notes/c.txt"
set_random_session_key

log_step "Bootstrapping lokeys config and mount"
# First list call bootstraps config/secure storage and mounts tmpfs insecure dir.
lk list

# Add each file to protection and verify add workflow handles multiple paths.
log_step "Protecting test files"
lk add "$TEST_HOME/docs/a.txt"
lk add "$TEST_HOME/ssh/id_test"
lk add "$TEST_HOME/notes/c.txt"

log_step "Editing insecure files and sealing"
# Modify plaintext in RAM-disk copies, then persist encrypted-at-rest state.
printf 'alpha-edited\n' >"$TEST_INSECURE_DIR/docs/a.txt"
printf 'bravo-edited\n' >"$TEST_INSECURE_DIR/ssh/id_test"
lk seal

list_after_seal="$(lk_capture list)"
printf '%s\n' "$list_after_seal"
# Ensure post-seal consistency checks report OK for all tracked files.
assert_list_status "$list_after_seal" "\$HOME/docs/a.txt" 'OK'
assert_list_status "$list_after_seal" "\$HOME/ssh/id_test" 'OK'
assert_list_status "$list_after_seal" "\$HOME/notes/c.txt" 'OK'
assert_no_list_status "$list_after_seal" 'MISMATCH'

log_step "Simulating reboot and validating unseal"
# Simulate reboot by clearing volatile insecure data only, then reconstruct via unseal.
clear_directory_contents "$TEST_INSECURE_DIR"
lk unseal
# Confirm unseal restored plaintext files and home symlinks correctly.
assert_file "$TEST_INSECURE_DIR/docs/a.txt"
assert_file "$TEST_INSECURE_DIR/ssh/id_test"
assert_file "$TEST_INSECURE_DIR/notes/c.txt"
assert_symlink_target "$TEST_HOME/docs/a.txt" "$TEST_INSECURE_DIR/docs/a.txt"
assert_symlink_target "$TEST_HOME/ssh/id_test" "$TEST_INSECURE_DIR/ssh/id_test"
assert_symlink_target "$TEST_HOME/notes/c.txt" "$TEST_INSECURE_DIR/notes/c.txt"

log_step "Validating pause/unpause behavior"
# Pause one managed file, verify unseal skips it, ensure list reports PAUSED,
# verify seal succeeds while paused file is missing from insecure, then unpause.
pause_output_first="$(lk_capture pause "$TEST_HOME/notes/c.txt")"
assert_output_contains "$pause_output_first" "paused \$HOME/notes/c.txt"
pause_output_second="$(lk_capture pause "$TEST_HOME/notes/c.txt")"
assert_output_contains "$pause_output_second" "\$HOME/notes/c.txt already paused."
clear_directory_contents "$TEST_INSECURE_DIR"
lk unseal
assert_file "$TEST_INSECURE_DIR/docs/a.txt"
assert_file "$TEST_INSECURE_DIR/ssh/id_test"
[ ! -e "$TEST_INSECURE_DIR/notes/c.txt" ] || fail "expected paused file to remain absent: $TEST_INSECURE_DIR/notes/c.txt"

list_after_pause="$(lk_capture list)"
printf '%s\n' "$list_after_pause"
assert_list_status "$list_after_pause" "\$HOME/notes/c.txt" 'MISSING_INSECURE'
assert_list_paused "$list_after_pause" "\$HOME/notes/c.txt"
assert_list_not_paused "$list_after_pause" "\$HOME/docs/a.txt"

lk seal

unpause_output_first="$(lk_capture unpause "$TEST_HOME/notes/c.txt")"
assert_output_contains "$unpause_output_first" "unpaused \$HOME/notes/c.txt"
unpause_output_second="$(lk_capture unpause "$TEST_HOME/notes/c.txt")"
assert_output_contains "$unpause_output_second" "\$HOME/notes/c.txt already unpaused."
clear_directory_contents "$TEST_INSECURE_DIR"
lk unseal
assert_file "$TEST_INSECURE_DIR/notes/c.txt"
assert_symlink_target "$TEST_HOME/notes/c.txt" "$TEST_INSECURE_DIR/notes/c.txt"

log_step "Rotating symmetric key and verifying seal/unseal"
# Generate deterministic test rotation key material so rotate can run unattended.
rotate_new_key="$(openssl rand -base64 32)"
log_info "generated rotation key for non-interactive rotate"
export LOKEYS_ROTATE_NEW_KEY="$rotate_new_key"
printf 'Rotation uses auto-generated NEW key via LOKEYS_ROTATE_NEW_KEY; previous key comes from LOKEYS_SESSION_KEY.\n'
lk rotate
# After rotate, switch session key to the new key for subsequent commands.
unset LOKEYS_ROTATE_NEW_KEY
export LOKEYS_SESSION_KEY="$rotate_new_key"
log_info "updated LOKEYS_SESSION_KEY to rotated key"
lk seal
clear_directory_contents "$TEST_INSECURE_DIR"
lk unseal
list_after_rotate="$(lk_capture list)"
printf '%s\n' "$list_after_rotate"
# Validate rotated key still supports full seal/unseal/list lifecycle.
assert_list_status "$list_after_rotate" "\$HOME/docs/a.txt" 'OK'
assert_list_status "$list_after_rotate" "\$HOME/ssh/id_test" 'OK'
assert_list_status "$list_after_rotate" "\$HOME/notes/c.txt" 'OK'

log_step "Testing backup and restore"
# Capture backup path, keep a copy outside secure dir, then wipe runtime state.
backup_output="$(lk_capture backup)"
printf '%s\n' "$backup_output"
backup_path="$(printf '%s\n' "$backup_output" | sed -n 's/^backup created: //p')"
[ -n "$backup_path" ] || fail "failed to parse backup path from output"
assert_file "$backup_path"
saved_backup="$TEST_WORK_DIR/$(basename "$backup_path")"
cp "$backup_path" "$saved_backup"
assert_file "$saved_backup"

rm -f "$TEST_CONFIG_PATH"
unmount_if_mounted "$TEST_INSECURE_DIR"
rm -rf "$TEST_SECURE_DIR" "$TEST_INSECURE_DIR" "$TEST_HOME/docs" "$TEST_HOME/ssh" "$TEST_HOME/notes"
mkdir -p "$TEST_SECURE_DIR" "$TEST_INSECURE_DIR"
cp "$saved_backup" "$TEST_SECURE_DIR/"
restored_backup="$TEST_SECURE_DIR/$(basename "$saved_backup")"
assert_file "$restored_backup"

lk restore "$restored_backup"
# Recreate home parent dirs before unseal relinks managed paths.
mkdir -p "$TEST_HOME/docs" "$TEST_HOME/ssh" "$TEST_HOME/notes"
lk unseal
list_after_restore="$(lk_capture list)"
printf '%s\n' "$list_after_restore"
assert_list_status "$list_after_restore" "\$HOME/docs/a.txt" 'OK'
assert_list_status "$list_after_restore" "\$HOME/ssh/id_test" 'OK'
assert_list_status "$list_after_restore" "\$HOME/notes/c.txt" 'OK'

printf '\nLocal workflow integration test: PASS\n'
