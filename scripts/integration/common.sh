#!/usr/bin/env bash
set -euo pipefail

timestamp() {
	date '+%Y-%m-%d %H:%M:%S'
}

log_info() {
	printf '[%s] INFO: %s\n' "$(timestamp)" "$1" >&2
}

log_step() {
	printf '\n[%s] ==> %s\n' "$(timestamp)" "$1"
}

fail() {
	printf '[%s] ERROR: %s\n' "$(timestamp)" "$1" >&2
	exit 1
}

require_cmd() {
	command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

require_tty() {
	[ -t 0 ] || fail "integration workflow requires an interactive terminal"
}

create_temp_layout() {
	local root
	root="$(mktemp -d)"
	TEST_ROOT="$root"
	TEST_HOME="$root/home"
	TEST_CONFIG_DIR="$root/config"
	TEST_SECURE_DIR="$root/secure"
	TEST_INSECURE_DIR="$root/insecure"
	TEST_WORK_DIR="$root/work"
	TEST_CONFIG_PATH="$TEST_CONFIG_DIR/lokeys.json"

	mkdir -p "$TEST_HOME" "$TEST_CONFIG_DIR" "$TEST_SECURE_DIR" "$TEST_INSECURE_DIR" "$TEST_WORK_DIR"

	export HOME="$TEST_HOME"
	export LOKEYS_HOME="$TEST_HOME"
	export LOKEYS_CONFIG_PATH="$TEST_CONFIG_PATH"
	export LOKEYS_SECURE_DIR="$TEST_SECURE_DIR"
	export LOKEYS_INSECURE_DIR="$TEST_INSECURE_DIR"
}

cleanup_layout() {
	unmount_if_mounted "${TEST_INSECURE_DIR:-}"
	if [ -n "${TEST_ROOT:-}" ] && [ -d "$TEST_ROOT" ]; then
		chmod -R u+w "$TEST_ROOT" 2>/dev/null || true
		rm -rf "$TEST_ROOT" || true
	fi
}

unmount_if_mounted() {
	local path="$1"
	[ -n "$path" ] || return 0
	if command -v mountpoint >/dev/null 2>&1 && mountpoint -q "$path"; then
		log_info "unmounting: $path"
		umount "$path" 2>/dev/null || true
		umount -l "$path" 2>/dev/null || true
		sudo -n umount "$path" 2>/dev/null || true
		sudo -n umount -l "$path" 2>/dev/null || true
	fi
}

clear_directory_contents() {
	local dir="$1"
	mkdir -p "$dir"
	shopt -s dotglob nullglob
	local entries=("$dir"/*)
	if [ ${#entries[@]} -gt 0 ]; then
		rm -rf "${entries[@]}"
	fi
	shopt -u dotglob nullglob
}

lk() {
	local -a cmd
	if [ -n "${LOKEYS_BIN:-}" ]; then
		cmd=("$LOKEYS_BIN" --verbose "$@")
	else
		cmd=(go run ./cmd/lokeys --verbose "$@")
	fi
	log_info "run: ${cmd[*]}"
	"${cmd[@]}"
}

lk_capture() {
	local -a cmd
	if [ -n "${LOKEYS_BIN:-}" ]; then
		cmd=("$LOKEYS_BIN" --verbose "$@")
	else
		cmd=(go run ./cmd/lokeys --verbose "$@")
	fi
	log_info "run(capture): ${cmd[*]}"
	"${cmd[@]}"
}

set_random_session_key() {
	require_cmd openssl
	export LOKEYS_SESSION_KEY
	LOKEYS_SESSION_KEY="$(openssl rand -base64 32)"
}

assert_file() {
	[ -f "$1" ] || fail "expected file: $1"
}

assert_symlink_target() {
	local path="$1"
	local expected="$2"
	[ -L "$path" ] || fail "expected symlink: $path"
	local target
	target="$(readlink "$path")"
	[ "$target" = "$expected" ] || fail "symlink target mismatch for $path: got $target want $expected"
}

assert_list_status() {
	local list_output="$1"
	local portable_path="$2"
	local status="$3"
	printf '%s\n' "$list_output" | grep -F "${portable_path}  " | grep -F "${status}" >/dev/null || fail "expected status ${status} for ${portable_path}"
}

assert_list_paused() {
	local list_output="$1"
	local portable_path="$2"
	printf '%s\n' "$list_output" | grep -F "${portable_path}  " | grep -F 'PAUSED' >/dev/null || fail "expected PAUSED marker for ${portable_path}"
}

assert_list_not_paused() {
	local list_output="$1"
	local portable_path="$2"
	if printf '%s\n' "$list_output" | grep -F "${portable_path}  " | grep -F 'PAUSED' >/dev/null; then
		fail "did not expect PAUSED marker for ${portable_path}"
	fi
}

assert_output_contains() {
	local output="$1"
	local expected="$2"
	printf '%s\n' "$output" | grep -F "$expected" >/dev/null || fail "expected output to contain: $expected"
}

assert_no_list_status() {
	local list_output="$1"
	local status="$2"
	if printf '%s\n' "$list_output" | grep -E "  ${status}$" >/dev/null; then
		fail "unexpected status present: ${status}"
	fi
}

assert_path_exists_only() {
	local path="$1"
	local description="$2"
	[ -e "$path" ] || fail "expected ${description} to exist: $path"
}

log_layout() {
	log_info "TEST_ROOT=$TEST_ROOT"
	log_info "HOME=$TEST_HOME"
	log_info "LOKEYS_CONFIG_PATH=$TEST_CONFIG_PATH"
	log_info "LOKEYS_SECURE_DIR=$TEST_SECURE_DIR"
	log_info "LOKEYS_INSECURE_DIR=$TEST_INSECURE_DIR"
	if [ -n "${AWS_PROFILE:-}" ]; then
		log_info "AWS_PROFILE=$AWS_PROFILE"
	fi
	if [ -n "${AWS_REGION:-}" ]; then
		log_info "AWS_REGION=$AWS_REGION"
	fi
}
