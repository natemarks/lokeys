#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=scripts/integration/common.sh
source "$(dirname "$0")/common.sh"

require_cmd readlink
require_tty

[ -n "${AWS_PROFILE:-}" ] || fail "AWS_PROFILE is required"

create_temp_layout
trap cleanup_layout EXIT
log_layout

AWS_REGION_VALUE="${AWS_REGION:-}"
KMS_ALIAS_VALUE="${KMS_ALIAS:-alias/lokeys-itest}"

log_step "Initializing KMS workflow test layout"
mkdir -p "$TEST_HOME/docs" "$TEST_HOME/.aws"
printf 'kms-alpha\n' >"$TEST_HOME/docs/a.txt"
printf '[default]\nregion=us-east-1\n' >"$TEST_HOME/.aws/config"
set_random_session_key

log_step "Bootstrapping lokeys config and mount"
lk list

log_step "Enabling AWS KMS integration"
enable_args=(enable-kms --apply --alias "$KMS_ALIAS_VALUE" --profile "$AWS_PROFILE")
if [ -n "$AWS_REGION_VALUE" ]; then
	enable_args+=(--region "$AWS_REGION_VALUE")
fi
lk "${enable_args[@]}"

log_step "Protecting KMS-managed and bypassed files"
lk add "$TEST_HOME/docs/a.txt"
lk add --allow-kms-bypass "$TEST_HOME/.aws/config"

log_step "Editing, sealing, and validating consistency"
printf 'kms-alpha-edited\n' >"$TEST_INSECURE_DIR/docs/a.txt"
printf '[default]\nregion=us-west-2\n' >"$TEST_INSECURE_DIR/.aws/config"
lk seal
list_after_seal="$(lk_capture list)"
printf '%s\n' "$list_after_seal"
assert_list_status "$list_after_seal" "\$HOME/docs/a.txt" 'OK'
assert_list_status "$list_after_seal" "\$HOME/.aws/config" 'OK'

log_step "Simulating reboot and validating unseal links"
clear_directory_contents "$TEST_INSECURE_DIR"
lk unseal
assert_file "$TEST_INSECURE_DIR/docs/a.txt"
assert_file "$TEST_INSECURE_DIR/.aws/config"
assert_symlink_target "$TEST_HOME/docs/a.txt" "$TEST_INSECURE_DIR/docs/a.txt"
assert_symlink_target "$TEST_HOME/.aws/config" "$TEST_INSECURE_DIR/.aws/config"

log_step "Rotating symmetric key and re-validating"
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
assert_list_status "$list_after_rotate" "\$HOME/.aws/config" 'OK'

log_step "Testing backup and restore with KMS"
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
rm -rf "$TEST_SECURE_DIR" "$TEST_INSECURE_DIR" "$TEST_HOME/docs" "$TEST_HOME/.aws"
mkdir -p "$TEST_SECURE_DIR" "$TEST_INSECURE_DIR"
cp "$saved_backup" "$TEST_SECURE_DIR/"
restored_backup="$TEST_SECURE_DIR/$(basename "$saved_backup")"
assert_path_exists_only "$restored_backup" "backup archive"

lk restore "$restored_backup"
lk unseal
list_after_restore="$(lk_capture list)"
printf '%s\n' "$list_after_restore"
assert_list_status "$list_after_restore" "\$HOME/docs/a.txt" 'OK'
assert_list_status "$list_after_restore" "\$HOME/.aws/config" 'OK'

printf '\nKMS workflow integration test: PASS\n'
