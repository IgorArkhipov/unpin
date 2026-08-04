#!/bin/sh
set -eu

workspace_root="$(cd "$SRCROOT/../.." && pwd)"
target_directory="$workspace_root/target/debug"
binary="$target_directory/unpin"
bundle_macos="$TARGET_BUILD_DIR/$CONTENTS_FOLDER_PATH/MacOS"
bundle_resources="$TARGET_BUILD_DIR/$CONTENTS_FOLDER_PATH/Resources"

cargo build --locked --manifest-path "$workspace_root/Cargo.toml" -p unpin-cli

if [ ! -x "$binary" ]; then
  echo "expected bundled Unpin binary at $binary" >&2
  exit 1
fi

mkdir -p "$bundle_macos" "$bundle_resources"
ditto "$binary" "$bundle_macos/unpin"
version="$($binary --version | awk '{print $2}')"
digest="$(shasum -a 256 "$bundle_macos/unpin" | awk '{print $1}')"
printf '{"bridgeProtocolVersion":1,"unpinVersion":"%s","sha256":"%s"}\n' "$version" "$digest" > "$bundle_resources/unpin-bridge-manifest.json"
