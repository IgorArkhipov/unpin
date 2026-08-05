#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 3 ]]; then
  echo "usage: scripts/verify_desktop_release_artifact.sh ARCHIVE TARGET VERSION" >&2
  exit 2
fi

archive="$1"
release_target="$2"
release_version="$3"

case "$release_target" in
  aarch64-apple-darwin) expected_architecture="arm64" ;;
  x86_64-apple-darwin) expected_architecture="x86_64" ;;
  *)
    echo "unsupported desktop release target: $release_target" >&2
    exit 2
    ;;
esac

if [[ ! -f "$archive" || -L "$archive" ]]; then
  echo "desktop release archive is missing or unsafe: $archive" >&2
  exit 1
fi

release_name="unpin-desktop-v${release_version}-${release_target}"
expected_archive_name="$release_name.tar.gz"
if [[ "$(basename "$archive")" != "$expected_archive_name" ]]; then
  echo "desktop release archive name does not match $expected_archive_name" >&2
  exit 1
fi

smoke_root="$(mktemp -d)"
if [[ -z "$smoke_root" || ! -d "$smoke_root" ]]; then
  echo "failed to create desktop artifact smoke directory" >&2
  exit 1
fi
trap 'rm -rf -- "$smoke_root"' EXIT

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
fixture_source="$repository_root/crates/unpin-core/tests/fixtures"
if [[ ! -d "$fixture_source" ]]; then
  echo "desktop artifact smoke fixtures are missing: $fixture_source" >&2
  exit 1
fi

tar -xzf "$archive" -C "$smoke_root"
app="$smoke_root/$release_name/UnpinDesktop.app"
desktop_binary="$app/Contents/MacOS/UnpinDesktop"
bridge_binary="$app/Contents/MacOS/unpin"
manifest="$app/Contents/Resources/unpin-bridge-manifest.json"
for required in "$desktop_binary" "$bridge_binary" "$manifest"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "desktop release archive is missing required file: $required" >&2
    exit 1
  fi
done

if [[ "$(lipo -archs "$desktop_binary")" != "$expected_architecture" ]]; then
  echo "desktop archive executable architecture mismatch" >&2
  exit 1
fi
if [[ "$(lipo -archs "$bridge_binary")" != "$expected_architecture" ]]; then
  echo "desktop archive bridge architecture mismatch" >&2
  exit 1
fi

codesign --verify --deep --strict --verbose=2 "$app"
app_version="$(plutil -extract CFBundleShortVersionString raw "$app/Contents/Info.plist")"
if [[ "$app_version" != "$release_version" ]]; then
  echo "desktop app version $app_version does not match $release_version" >&2
  exit 1
fi

python3 - "$manifest" "$bridge_binary" "$release_version" <<'PY'
import hashlib
import json
import pathlib
import sys

manifest_path = pathlib.Path(sys.argv[1])
bridge_path = pathlib.Path(sys.argv[2])
expected_version = sys.argv[3]
payload = json.loads(manifest_path.read_text(encoding="utf-8"))
if payload != {
    "bridgeProtocolVersion": 2,
    "unpinVersion": expected_version,
    "sha256": hashlib.sha256(bridge_path.read_bytes()).hexdigest(),
}:
    raise SystemExit("desktop bridge manifest does not match bundled binary")
PY

version_output="$(
  env -i \
    HOME="$smoke_root" \
    PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
    TMPDIR="$smoke_root" \
    LC_ALL=C \
    arch "-$expected_architecture" "$bridge_binary" --version
)"
if [[ "$version_output" != "unpin $release_version" ]]; then
  echo "desktop archive bridge version mismatch: $version_output" >&2
  exit 1
fi

home_root="$smoke_root/home"
fixture_root="$smoke_root/fixtures"
project_root="$smoke_root/workspace"
app_state_root="$smoke_root/app-state"
tmp_root="$smoke_root/tmp"
mkdir -p "$home_root" "$project_root/.git" "$app_state_root" "$tmp_root"

# Use the committed provider fixtures, but copy them into the smoke sandbox so
# the bundled bridge cannot consult repository or user state. Ignore .env*
# files defensively even though committed fixtures must not contain them.
python3 - "$fixture_source" "$fixture_root" <<'PY'
import pathlib
import shutil
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
shutil.copytree(
    source,
    destination,
    symlinks=True,
    ignore=shutil.ignore_patterns(".env*"),
)
PY

request_file="$smoke_root/bridge-requests.jsonl"
response_file="$smoke_root/bridge-responses.jsonl"
stderr_file="$smoke_root/bridge.stderr"
printf '%s\n' \
  '{"version":2,"id":"archive-handshake","method":"handshake","params":{}}' \
  '{"version":2,"id":"archive-snapshot","method":"snapshot","params":{}}' \
  '{"version":2,"id":"archive-shutdown","method":"shutdown","params":{}}' \
  > "$request_file"

# An empty environment plus explicit roots makes accidental HOME/provider
# lookups observable and keeps this smoke independent of the host account.
(
  cd "$smoke_root"
  env -i \
    HOME="$home_root" \
    PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
    TMPDIR="$tmp_root" \
    LC_ALL=C \
    arch "-$expected_architecture" "$bridge_binary" desktop bridge \
      --fixture-root "$fixture_root" \
      --home-root "$home_root" \
      --project-root "$project_root" \
      --app-state-root "$app_state_root" \
      < "$request_file" \
      > "$response_file" \
      2> "$stderr_file"
)
if [[ -s "$stderr_file" ]]; then
  echo "desktop archive bridge emitted unexpected diagnostics" >&2
  cat "$stderr_file" >&2
  exit 1
fi

python3 "$repository_root/scripts/validate_desktop_release_projection.py" \
  "$response_file" "$release_version"

printf 'desktop artifact verified: %s (%s)\n' "$expected_archive_name" "$expected_architecture"
