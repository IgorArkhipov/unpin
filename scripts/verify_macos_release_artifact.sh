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
broker="$smoke_root/$release_name/unpin-credential-broker"
for required_binary in "$binary" "$broker"; do
  if [[ ! -f "$required_binary" || -L "$required_binary" ]]; then
    echo "macOS release archive is missing required binary: $required_binary" >&2
    exit 1
  fi
  if [[ "$(lipo -archs "$required_binary")" != "$expected_architecture" ]]; then
    echo "macOS release archive executable architecture mismatch: $required_binary" >&2
    exit 1
  fi
done

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
"$repository_root/scripts/verify_macos_artifact_signature.sh" \
  dev.unpin.cli \
  "$binary"
"$repository_root/scripts/verify_macos_artifact_signature.sh" \
  dev.unpin.credential-broker \
  "$broker"

broker_timeout_seconds="${UNPIN_MACOS_RELEASE_BROKER_TIMEOUT_SECONDS:-30}"
python3_binary="$(command -v python3 || true)"
smoke_driver="$repository_root/scripts/run_authenticated_desktop_bridge_smoke.py"
if [[ -z "$python3_binary" || ! -x "$python3_binary" ]]; then
  echo "python3 is required for bounded credential broker verification" >&2
  exit 1
fi
if [[ ! -f "$smoke_driver" || -L "$smoke_driver" ]]; then
  echo "bounded credential broker smoke driver is missing or unsafe" >&2
  exit 1
fi
broker_version_output_file="$smoke_root/broker-version.out"
set +e
env -i \
  HOME="$smoke_root" \
  PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
  TMPDIR="$smoke_root" \
  LC_ALL=C \
  "$python3_binary" "$smoke_driver" \
    --timeout-seconds "$broker_timeout_seconds" \
    --stdout-file "$broker_version_output_file" \
    -- \
    arch "-$expected_architecture" "$broker" --version
broker_status=$?
set -e
if [[ "$broker_status" -ne 0 ]]; then
  if [[ "$broker_status" -eq 124 ]]; then
    echo "macOS CLI credential broker timed out during version verification" >&2
  fi
  exit "$broker_status"
fi
broker_version_output="$(<"$broker_version_output_file")"
if [[ "$broker_version_output" != "unpin-credential-broker $release_version protocol 1" ]]; then
  echo "macOS CLI credential broker version mismatch: $broker_version_output" >&2
  exit 1
fi

printf 'macOS CLI artifact verified: %s (%s)\n' "$expected_archive_name" "$expected_architecture"
