#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -lt 3 || "$#" -gt 4 ]]; then
  echo "usage: scripts/build_desktop_release.sh TARGET VERSION OUTPUT_DIRECTORY [build-only]" >&2
  exit 2
fi

release_target="$1"
release_version="$2"
release_output="$3"
build_mode="${4:-full}"

case "$build_mode" in
  full | build-only) ;;
  *)
    echo "unsupported desktop release build mode: $build_mode" >&2
    exit 2
    ;;
esac

case "$release_target" in
  aarch64-apple-darwin) xcode_architecture="arm64" ;;
  x86_64-apple-darwin) xcode_architecture="x86_64" ;;
  *)
    echo "unsupported desktop release target: $release_target" >&2
    exit 2
    ;;
esac

if [[ ! "$release_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid desktop release version: $release_version" >&2
  exit 2
fi

repository_root="$(git rev-parse --show-toplevel)"
if [[ -e "$release_output" && -L "$release_output" ]]; then
  echo "desktop release output directory is an unsafe symlink: $release_output" >&2
  exit 1
fi
mkdir -p "$release_output"
build_root="$(mktemp -d)"
if [[ -z "$build_root" || ! -d "$build_root" ]]; then
  echo "failed to create desktop release build directory" >&2
  exit 1
fi
trap 'rm -rf -- "$build_root"' EXIT

derived_data="$build_root/DerivedData"
# Stdout is a machine-readable contract: exactly one line containing the
# resulting archive path. Keep Xcode's diagnostics on stderr so callers can
# safely capture stdout without losing build failures or logs.
UNPIN_RUST_TARGET="$release_target" xcodebuild build \
  -project "$repository_root/apps/unpin-desktop/UnpinDesktop.xcodeproj" \
  -scheme UnpinDesktop \
  -configuration Release \
  -destination "platform=macOS,arch=$xcode_architecture" \
  -derivedDataPath "$derived_data" \
  ARCHS="$xcode_architecture" \
  ONLY_ACTIVE_ARCH=YES \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  MARKETING_VERSION="$release_version" >&2

app="$derived_data/Build/Products/Release/UnpinDesktop.app"
desktop_binary="$app/Contents/MacOS/UnpinDesktop"
bridge_binary="$app/Contents/MacOS/unpin"
manifest="$app/Contents/Resources/unpin-bridge-manifest.json"
for required in "$desktop_binary" "$bridge_binary" "$manifest"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "desktop release output is missing or unsafe: $required" >&2
    exit 1
  fi
done

if [[ "$(lipo -archs "$desktop_binary")" != "$xcode_architecture" ]]; then
  echo "desktop executable architecture does not match $xcode_architecture" >&2
  exit 1
fi
if [[ "$(lipo -archs "$bridge_binary")" != "$xcode_architecture" ]]; then
  echo "bundled bridge architecture does not match $xcode_architecture" >&2
  exit 1
fi

# Keep the unsigned Xcode output outside the temporary build root so a later,
# isolated signing step can consume the exact same app bundle. The hidden path
# is intentionally excluded by the workflow's dist/* upload glob.
staging_root="$release_output/.unpin-desktop-v${release_version}-${release_target}"
staged_app="$staging_root/UnpinDesktop.app"
if [[ -e "$staging_root" || -L "$staging_root" ]]; then
  echo "desktop release staging directory already exists or is unsafe: $staging_root" >&2
  exit 1
fi
mkdir -p "$staging_root"
cp -R "$app" "$staged_app"

if [[ "$build_mode" == "build-only" ]]; then
  printf '%s\n' "$staged_app"
  exit 0
fi

archive="$("$repository_root/scripts/sign_desktop_release.sh" \
  "$release_target" \
  "$release_version" \
  "$release_output")"
printf '%s\n' "$archive"
