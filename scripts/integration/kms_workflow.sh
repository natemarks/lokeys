#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=scripts/integration/common.sh
source "$(dirname "$0")/common.sh"

require_cmd readlink
require_tty

[ -n "${AWS_PROFILE:-}" ] || fail "AWS_PROFILE is required"

original_home="$HOME"

# Resolve AWS credentials before HOME override so SDK/profile lookup remains stable
# in the isolated temp test environment.
if command -v aws >/dev/null 2>&1; then
	if [ -z "${AWS_ACCESS_KEY_ID:-}" ]; then
		if creds_env="$(aws configure export-credentials --profile "$AWS_PROFILE" --format env 2>/dev/null)"; then
			eval "$creds_env"
			log_info "loaded AWS session credentials from profile before HOME override"
		fi
	fi
	aws sts get-caller-identity --profile "$AWS_PROFILE" >/dev/null
else
	fail "aws CLI is required for KMS integration workflow preflight"
fi

export AWS_EC2_METADATA_DISABLED=true
# Pin AWS shared config paths to the original HOME to avoid accidental lookup in
# the isolated temp HOME used by integration tests.
if [ -z "${AWS_SHARED_CREDENTIALS_FILE:-}" ] && [ -f "$original_home/.aws/credentials" ]; then
	export AWS_SHARED_CREDENTIALS_FILE="$original_home/.aws/credentials"
fi
if [ -z "${AWS_CONFIG_FILE:-}" ] && [ -f "$original_home/.aws/config" ]; then
	export AWS_CONFIG_FILE="$original_home/.aws/config"
fi

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
# First list call bootstraps config/secure storage and mounts tmpfs insecure dir.
lk list

log_step "Enabling AWS KMS integration"
# Apply mode creates/validates alias+CMK and writes KMS settings to config.
enable_args=(enable-kms --apply --alias "$KMS_ALIAS_VALUE" --profile "$AWS_PROFILE")
if [ -n "$AWS_REGION_VALUE" ]; then
	enable_args+=(--region "$AWS_REGION_VALUE")
fi
lk "${enable_args[@]}"

log_step "Protecting KMS-managed and bypassed files"
# docs/a.txt should use KMS envelope; ~/.aws/config is explicitly bypassed to
# avoid credential bootstrap loops.
lk add "$TEST_HOME/docs/a.txt"
lk add --allow-kms-bypass "$TEST_HOME/.aws/config"

log_step "Editing, sealing, and validating consistency"
# Edit volatile plaintext, seal to secure storage, and validate both policy paths:
# one KMS-managed file and one local-only bypass file.
printf 'kms-alpha-edited\n' >"$TEST_INSECURE_DIR/docs/a.txt"
printf '[default]\nregion=us-west-2\n' >"$TEST_INSECURE_DIR/.aws/config"
lk seal
list_after_seal="$(lk_capture list)"
printf '%s\n' "$list_after_seal"
assert_list_status "$list_after_seal" "\$HOME/docs/a.txt" 'OK'
assert_list_status "$list_after_seal" "\$HOME/.aws/config" 'OK'

log_step "Simulating reboot and validating unseal links"
# Simulate reboot by clearing volatile insecure data only, then recover from secure.
clear_directory_contents "$TEST_INSECURE_DIR"
lk unseal
assert_file "$TEST_INSECURE_DIR/docs/a.txt"
assert_file "$TEST_INSECURE_DIR/.aws/config"
assert_symlink_target "$TEST_HOME/docs/a.txt" "$TEST_INSECURE_DIR/docs/a.txt"
assert_symlink_target "$TEST_HOME/.aws/config" "$TEST_INSECURE_DIR/.aws/config"

log_step "Rotating symmetric key and re-validating"
# Rotate local symmetric key while preserving KMS policy split.
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
assert_list_status "$list_after_rotate" "\$HOME/docs/a.txt" 'OK'
assert_list_status "$list_after_rotate" "\$HOME/.aws/config" 'OK'

log_step "Testing backup and restore with KMS"
# Backup encrypted artifacts/config, wipe runtime state, restore archive,
# and prove KMS+local-bypass files both recover correctly.
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
# Recreate home parent dirs before unseal relinks managed paths.
mkdir -p "$TEST_HOME/docs" "$TEST_HOME/.aws"
lk unseal
list_after_restore="$(lk_capture list)"
printf '%s\n' "$list_after_restore"
assert_list_status "$list_after_restore" "\$HOME/docs/a.txt" 'OK'
assert_list_status "$list_after_restore" "\$HOME/.aws/config" 'OK'

printf '\nKMS workflow integration test: PASS\n'
