#!/usr/bin/env bash
set -euo pipefail

ramdisk_test_dir="${HOME}/.lokeys/insecure/lokeys_test"
data_dir="${HOME}/lokeys_test"

rm -rf "${data_dir}" "${ramdisk_test_dir}"
mkdir -p "${data_dir}/notes"

printf 'line 1\n' >"${data_dir}/file1.txt"
printf 'line 2\nline 3\n' >"${data_dir}/file2.txt"
printf 'alpha\nbeta\ngamma\n' >"${data_dir}/notes/alpha.txt"

printf 'reset complete: %s\n' "${data_dir}"
