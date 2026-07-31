#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "usage: scripts/verify_linux_release_artifact.sh BINARY" >&2
  exit 2
fi

binary="$1"
if [[ ! -f "$binary" || -L "$binary" ]]; then
  echo "release binary missing or unsafe: $binary" >&2
  exit 1
fi

max_supported_glibc="2.35"
max_glibc="$(
  readelf --version-info "$binary" \
    | awk '/Name: GLIBC_/ { match($0, /GLIBC_[0-9.]+/); print substr($0, RSTART + 6, RLENGTH - 6) }' \
    | sort -V \
    | tail -n 1
)"
if [[ -z "$max_glibc" ]]; then
  echo "release binary does not declare a GNU libc requirement: $binary" >&2
  exit 1
fi
if [[ "$(printf '%s\n' "$max_glibc" "$max_supported_glibc" | sort -V | tail -n 1)" != "$max_supported_glibc" ]]; then
  echo "release binary requires GLIBC_$max_glibc; expected GLIBC_$max_supported_glibc or older" >&2
  exit 1
fi

"$binary" --version
"$binary" --help >/dev/null

binary_dir="$(cd "$(dirname "$binary")" && pwd)"
binary_path="$binary_dir/$(basename "$binary")"
docker run --rm -v "$binary_path:/opt/unpin:ro" debian:12 sh -c \
  '/opt/unpin --version >/dev/null && /opt/unpin --help >/dev/null'
