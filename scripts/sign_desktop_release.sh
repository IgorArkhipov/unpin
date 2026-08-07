#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 3 ]]; then
  echo "usage: scripts/sign_desktop_release.sh TARGET VERSION OUTPUT_DIRECTORY" >&2
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
if [[ -e "$release_output" && -L "$release_output" ]]; then
  echo "desktop release output directory is an unsafe symlink: $release_output" >&2
  exit 1
fi

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
source_date_epoch="${SOURCE_DATE_EPOCH:-$(git -C "$repository_root" log -1 --format=%ct)}"
staging_root="$release_output/.unpin-desktop-v${release_version}-${release_target}"
app="$staging_root/UnpinDesktop.app"
desktop_binary="$app/Contents/MacOS/UnpinDesktop"
bridge_binary="$app/Contents/MacOS/unpin"
manifest="$app/Contents/Resources/unpin-bridge-manifest.json"
for required in "$desktop_binary" "$bridge_binary" "$manifest"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "desktop release staging output is missing or unsafe: $required" >&2
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

# Sign the Keychain-accessing bridge before recording its digest, then sign the
# outer app last. No build commands run in this script: the caller can expose
# the signing Keychain only for this isolated operation.
"$repository_root/scripts/sign_macos_artifact.sh" \
  dev.unpin.workbench.bridge \
  "$bridge_binary" >&2
bridge_digest="$(shasum -a 256 "$bridge_binary" | awk '{print $1}')"
printf '{"bridgeProtocolVersion":2,"unpinVersion":"%s","sha256":"%s"}\n' \
  "$release_version" "$bridge_digest" > "$manifest"
"$repository_root/scripts/sign_macos_artifact.sh" \
  dev.unpin.workbench \
  "$app" >&2

archive="$(python3 "$repository_root/scripts/package_desktop_release.py" \
  --app "$app" \
  --target "$release_target" \
  --version "$release_version" \
  --output-directory "$release_output" \
  --source-date-epoch "$source_date_epoch" \
  --resource "$repository_root/README.md" \
  --resource "$repository_root/LICENSE")"
if [[ -z "$archive" || "$archive" == *$'\n'* || "$archive" == *$'\r'* || ! -f "$archive" || -L "$archive" ]]; then
  echo "desktop release packager must print one existing archive path" >&2
  exit 1
fi
printf '%s\n' "$archive"
