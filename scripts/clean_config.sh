#!/usr/bin/env bash
set -euo pipefail

insecure_mount="${HOME}/.lokeys/insecure"

if mountpoint -q "${insecure_mount}"; then
	if ! umount "${insecure_mount}" 2>/dev/null; then
		if ! umount -l "${insecure_mount}" 2>/dev/null; then
			printf 'normal unmount failed, trying sudo unmount: %s\n' "${insecure_mount}" >&2
			if ! sudo -n umount "${insecure_mount}" 2>/dev/null; then
				sudo umount "${insecure_mount}" || true
			fi
			if mountpoint -q "${insecure_mount}"; then
				printf 'sudo unmount failed, trying sudo lazy unmount: %s\n' "${insecure_mount}" >&2
				if ! sudo -n umount -l "${insecure_mount}" 2>/dev/null; then
					sudo umount -l "${insecure_mount}" || true
				fi
			fi
		fi
	fi
fi

if mountpoint -q "${insecure_mount}"; then
	printf 'failed to unmount %s; close processes using it and retry\n' "${insecure_mount}" >&2
	exit 1
fi

rm -f "${HOME}/.config/lokeys"
rm -rf "${HOME}/.lokeys/insecure"
