#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 3 ]]; then
  echo "usage: scripts/verify_macos_release_artifact.sh ARCHIVE TARGET VERSION" >&2
  exit 2
fi

archive="$1"
release_target="$2"
release_version="$3"

case "$release_target" in
  aarch64-apple-darwin) expected_architecture="arm64" ;;
  x86_64-apple-darwin) expected_architecture="x86_64" ;;
  *)
    echo "unsupported macOS release target: $release_target" >&2
    exit 2
    ;;
esac
if [[ ! -f "$archive" || -L "$archive" ]]; then
  echo "macOS release archive is missing or unsafe: $archive" >&2
  exit 1
fi

release_name="unpin-v${release_version}-${release_target}"
expected_archive_name="$release_name.tar.gz"
if [[ "$(basename "$archive")" != "$expected_archive_name" ]]; then
  echo "macOS release archive name does not match $expected_archive_name" >&2
  exit 1
fi

smoke_root="$(mktemp -d)"
if [[ -z "$smoke_root" || ! -d "$smoke_root" ]]; then
  echo "failed to create macOS artifact smoke directory" >&2
  exit 1
fi
trap 'rm -rf -- "$smoke_root"' EXIT

tar -xzf "$archive" -C "$smoke_root"
binary="$smoke_root/$release_name/unpin"
if [[ ! -f "$binary" || -L "$binary" ]]; then
  echo "macOS release archive is missing required CLI binary: $binary" >&2
  exit 1
fi
if [[ "$(lipo -archs "$binary")" != "$expected_architecture" ]]; then
  echo "macOS CLI archive executable architecture mismatch" >&2
  exit 1
fi

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
"$repository_root/scripts/verify_macos_artifact_signature.sh" \
  dev.unpin.cli \
  "$binary"

printf 'macOS CLI artifact verified: %s (%s)\n' "$expected_archive_name" "$expected_architecture"
