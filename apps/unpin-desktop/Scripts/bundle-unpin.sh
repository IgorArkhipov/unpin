#!/bin/sh
set -eu

workspace_root="$(cd "$SRCROOT/../.." && pwd)"
configuration="${CONFIGURATION:-Debug}"
case "$configuration" in
  Debug)
    cargo_profile_args=""
    cargo_profile_directory="debug"
    ;;
  Release)
    cargo_profile_args="--release"
    cargo_profile_directory="release"
    ;;
  *)
    echo "unsupported Xcode configuration for bundled Unpin: $configuration" >&2
    exit 1
    ;;
esac

rust_target="${UNPIN_RUST_TARGET:-}"
if [ -z "$rust_target" ]; then
  set -- ${ARCHS:-}
  if [ "$#" -ne 1 ]; then
    echo "desktop builds require exactly one architecture, got: ${ARCHS:-none}" >&2
    exit 1
  fi
  case "$1" in
    arm64) rust_target="aarch64-apple-darwin" ;;
    x86_64) rust_target="x86_64-apple-darwin" ;;
    *)
      echo "unsupported desktop build architecture: $1" >&2
      exit 1
      ;;
  esac
fi

case "$rust_target" in
  aarch64-apple-darwin) expected_architecture="arm64" ;;
  x86_64-apple-darwin) expected_architecture="x86_64" ;;
  *)
    echo "unsupported bundled Unpin target: $rust_target" >&2
    exit 1
    ;;
esac

target_directory="$workspace_root/target/$rust_target/$cargo_profile_directory"
binary="$target_directory/unpin"
broker_binary="$target_directory/unpin-credential-broker"
bundle_macos="$TARGET_BUILD_DIR/$CONTENTS_FOLDER_PATH/MacOS"
bundle_resources="$TARGET_BUILD_DIR/$CONTENTS_FOLDER_PATH/Resources"

# shellcheck disable=SC2086
cargo build --locked --manifest-path "$workspace_root/Cargo.toml" \
  -p unpin-cli --bins --target "$rust_target" $cargo_profile_args

for required_binary in "$binary" "$broker_binary"; do
  if [ ! -x "$required_binary" ]; then
    echo "expected bundled Unpin binary at $required_binary" >&2
    exit 1
  fi
  if [ "$(lipo -archs "$required_binary")" != "$expected_architecture" ]; then
    echo "bundled Unpin binary architecture does not match $expected_architecture" >&2
    exit 1
  fi
done

package_id="$(cargo pkgid --manifest-path "$workspace_root/Cargo.toml" -p unpin-cli)"
case "$package_id" in
  *'#'*) version_fragment="${package_id##*#}" ;;
  *)
    echo "could not determine bundled Unpin version from Cargo package ID" >&2
    exit 1
    ;;
esac
version="${version_fragment##*@}"
if [ -z "$version" ]; then
  echo "Cargo package ID returned an empty bundled Unpin version" >&2
  exit 1
fi
if [ -n "${MARKETING_VERSION:-}" ] && [ "$version" != "$MARKETING_VERSION" ]; then
  echo "bundled Unpin version $version does not match app version $MARKETING_VERSION" >&2
  exit 1
fi
mkdir -p "$bundle_macos" "$bundle_resources"
ditto "$binary" "$bundle_macos/unpin"
ditto "$broker_binary" "$bundle_macos/unpin-credential-broker"
digest="$(shasum -a 256 "$bundle_macos/unpin" | awk '{print $1}')"
printf '{"bridgeProtocolVersion":2,"unpinVersion":"%s","sha256":"%s"}\n' "$version" "$digest" > "$bundle_resources/unpin-bridge-manifest.json"
