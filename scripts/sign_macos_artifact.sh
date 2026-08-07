#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  echo "usage: scripts/sign_macos_artifact.sh IDENTIFIER ARTIFACT" >&2
  exit 2
fi

signing_identifier="$1"
artifact="$2"
signing_identity="${UNPIN_CODESIGN_IDENTITY:--}"
timestamp_mode="${UNPIN_CODESIGN_TIMESTAMP_MODE:-none}"
require_stable_signing="${UNPIN_REQUIRE_STABLE_CODESIGN:-0}"

if [[ ! "$signing_identifier" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]]; then
  echo "invalid macOS signing identifier: $signing_identifier" >&2
  exit 2
fi

if [[ ! -e "$artifact" || -L "$artifact" ]]; then
  echo "macOS signing artifact is missing or unsafe: $artifact" >&2
  exit 1
fi

case "$timestamp_mode" in
  none) timestamp_argument="--timestamp=none" ;;
  secure) timestamp_argument="--timestamp" ;;
  *)
    echo "invalid UNPIN_CODESIGN_TIMESTAMP_MODE: $timestamp_mode (expected none or secure)" >&2
    exit 2
    ;;
esac

case "$require_stable_signing" in
  0 | 1) ;;
  *)
    echo "invalid UNPIN_REQUIRE_STABLE_CODESIGN: $require_stable_signing (expected 0 or 1)" >&2
    exit 2
    ;;
esac

if [[ -z "$signing_identity" ]]; then
  echo "UNPIN_CODESIGN_IDENTITY must not be empty" >&2
  exit 2
fi
if [[ "$require_stable_signing" == "1" && "$signing_identity" == "-" ]]; then
  echo "stable macOS signing is required, but UNPIN_CODESIGN_IDENTITY is ad-hoc (-)" >&2
  exit 1
fi

codesign \
  --force \
  --sign "$signing_identity" \
  --identifier "$signing_identifier" \
  "$timestamp_argument" \
  --options runtime \
  "$artifact" >&2
codesign --verify --strict --verbose=2 "$artifact" >&2

signature_details="$(codesign --display --verbose=4 "$artifact" 2>&1)"
reported_identifier=""
while IFS= read -r detail; do
  case "$detail" in
    Identifier=*)
      reported_identifier="${detail#Identifier=}"
      break
      ;;
  esac
done <<< "$signature_details"

if [[ "$reported_identifier" != "$signing_identifier" ]]; then
  echo "macOS signature identifier mismatch: expected $signing_identifier, got ${reported_identifier:-<missing>}" >&2
  exit 1
fi

if [[ "$require_stable_signing" == "1" ]]; then
  while IFS= read -r detail; do
    if [[ "$detail" == "Signature=adhoc" ]]; then
      echo "stable macOS signing was required, but codesign produced an ad-hoc signature" >&2
      exit 1
    fi
  done <<< "$signature_details"
fi
