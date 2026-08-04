#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 3 ]]; then
  echo "usage: scripts/build_desktop_release.sh TARGET VERSION OUTPUT_DIRECTORY" >&2
  exit 2
fi

release_target="$1"
release_version="$2"
release_output="$3"

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
source_date_epoch="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
build_root="$(mktemp -d)"
if [[ -z "$build_root" || ! -d "$build_root" ]]; then
  echo "failed to create desktop release build directory" >&2
  exit 1
fi
trap 'rm -rf -- "$build_root"' EXIT

derived_data="$build_root/DerivedData"
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
  MARKETING_VERSION="$release_version"

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

# RC artifacts are intentionally ad-hoc signed. The absent timestamp makes the
# signing step reproducible, while Hardened Runtime keeps the bundle compatible
# with a future Developer ID/notarization release process.
codesign --force --sign - --timestamp=none --options runtime "$bridge_binary"
bridge_digest="$(shasum -a 256 "$bridge_binary" | awk '{print $1}')"
printf '{"bridgeProtocolVersion":2,"unpinVersion":"%s","sha256":"%s"}\n' \
  "$release_version" "$bridge_digest" > "$manifest"
codesign --force --sign - --timestamp=none --options runtime "$app"
codesign --verify --deep --strict --verbose=2 "$app"

python3 "$repository_root/scripts/package_desktop_release.py" \
  --app "$app" \
  --target "$release_target" \
  --version "$release_version" \
  --output-directory "$release_output" \
  --source-date-epoch "$source_date_epoch" \
  --resource "$repository_root/README.md" \
  --resource "$repository_root/LICENSE"
