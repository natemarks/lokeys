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

log_step "Initializing local workflow test layout"
mkdir -p "$TEST_HOME/docs" "$TEST_HOME/ssh" "$TEST_HOME/notes"
printf 'alpha\n' >"$TEST_HOME/docs/a.txt"
printf 'bravo\n' >"$TEST_HOME/ssh/id_test"
printf 'charlie\n' >"$TEST_HOME/notes/c.txt"
set_random_session_key

log_step "Bootstrapping lokeys config and mount"
lk list

log_step "Protecting test files"
lk add "$TEST_HOME/docs/a.txt"
lk add "$TEST_HOME/ssh/id_test"
lk add "$TEST_HOME/notes/c.txt"

log_step "Editing insecure files and sealing"
printf 'alpha-edited\n' >"$TEST_INSECURE_DIR/docs/a.txt"
printf 'bravo-edited\n' >"$TEST_INSECURE_DIR/ssh/id_test"
lk seal

list_after_seal="$(lk_capture list)"
printf '%s\n' "$list_after_seal"
assert_list_status "$list_after_seal" "\$HOME/docs/a.txt" 'OK'
assert_list_status "$list_after_seal" "\$HOME/ssh/id_test" 'OK'
assert_list_status "$list_after_seal" "\$HOME/notes/c.txt" 'OK'
assert_no_list_status "$list_after_seal" 'MISMATCH'

log_step "Simulating reboot and validating unseal"
clear_directory_contents "$TEST_INSECURE_DIR"
lk unseal
assert_file "$TEST_INSECURE_DIR/docs/a.txt"
assert_file "$TEST_INSECURE_DIR/ssh/id_test"
assert_file "$TEST_INSECURE_DIR/notes/c.txt"
assert_symlink_target "$TEST_HOME/docs/a.txt" "$TEST_INSECURE_DIR/docs/a.txt"
assert_symlink_target "$TEST_HOME/ssh/id_test" "$TEST_INSECURE_DIR/ssh/id_test"
assert_symlink_target "$TEST_HOME/notes/c.txt" "$TEST_INSECURE_DIR/notes/c.txt"

log_step "Rotating symmetric key and verifying seal/unseal"
printf 'Rotate requires interactive new-key prompt.\n'
lk rotate
log_step "Refreshing session key to rotated value"
refresh_session_key_from_prompt
lk seal
clear_directory_contents "$TEST_INSECURE_DIR"
lk unseal
list_after_rotate="$(lk_capture list)"
printf '%s\n' "$list_after_rotate"
assert_list_status "$list_after_rotate" "\$HOME/docs/a.txt" 'OK'
assert_list_status "$list_after_rotate" "\$HOME/ssh/id_test" 'OK'
assert_list_status "$list_after_rotate" "\$HOME/notes/c.txt" 'OK'

log_step "Testing backup and restore"
backup_output="$(lk_capture backup)"
printf '%s\n' "$backup_output"
backup_path="$(printf '%s\n' "$backup_output" | sed -n 's/^backup created: //p')"
[ -n "$backup_path" ] || fail "failed to parse backup path from output"
assert_file "$backup_path"

rm -f "$TEST_CONFIG_PATH"
unmount_if_mounted "$TEST_INSECURE_DIR"
rm -rf "$TEST_SECURE_DIR" "$TEST_INSECURE_DIR" "$TEST_HOME/docs" "$TEST_HOME/ssh" "$TEST_HOME/notes"
mkdir -p "$TEST_SECURE_DIR" "$TEST_INSECURE_DIR"
cp "$backup_path" "$TEST_SECURE_DIR/"
restored_backup="$TEST_SECURE_DIR/$(basename "$backup_path")"
assert_file "$restored_backup"

lk restore "$restored_backup"
lk unseal
list_after_restore="$(lk_capture list)"
printf '%s\n' "$list_after_restore"
assert_list_status "$list_after_restore" "\$HOME/docs/a.txt" 'OK'
assert_list_status "$list_after_restore" "\$HOME/ssh/id_test" 'OK'
assert_list_status "$list_after_restore" "\$HOME/notes/c.txt" 'OK'

printf '\nLocal workflow integration test: PASS\n'
