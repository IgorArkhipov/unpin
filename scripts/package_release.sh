#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 3 ]]; then
  echo "usage: scripts/package_release.sh TARGET VERSION OUTPUT_DIRECTORY" >&2
  exit 2
fi

release_target="$1"
release_version="$2"
release_output="$3"

case "$release_target" in
  aarch64-apple-darwin | x86_64-apple-darwin | x86_64-unknown-linux-gnu) ;;
  *)
    echo "unsupported release target: $release_target" >&2
    exit 2
    ;;
esac

if [[ ! "$release_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid release version: $release_version" >&2
  exit 2
fi

release_binary="target/$release_target/release/unpin"
if [[ ! -f "$release_binary" || -L "$release_binary" ]]; then
  echo "release binary is missing or unsafe: $release_binary" >&2
  exit 1
fi

release_stage="$(mktemp -d)"
if [[ -z "$release_stage" || ! -d "$release_stage" ]]; then
  echo "failed to create release staging directory" >&2
  exit 1
fi
trap 'rm -rf -- "$release_stage"' EXIT

release_name="unpin-v${release_version}-${release_target}"
release_root="$release_stage/$release_name"
mkdir -p "$release_root" "$release_output"

install -m 0755 "$release_binary" "$release_root/unpin"
install -m 0644 README.md LICENSE "$release_root/"

tar -czf "$release_output/$release_name.tar.gz" \
  -C "$release_stage" \
  "$release_name"

printf '%s\n' "$release_output/$release_name.tar.gz"
