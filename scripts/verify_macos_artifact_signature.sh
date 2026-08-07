#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  echo "usage: scripts/verify_macos_artifact_signature.sh IDENTIFIER ARTIFACT" >&2
  exit 2
fi

expected_identifier="$1"
artifact="$2"
require_stable_signing="${UNPIN_REQUIRE_STABLE_CODESIGN:-0}"
expected_fingerprint="${UNPIN_CODESIGN_EXPECTED_FINGERPRINT:-}"

if [[ ! "$expected_identifier" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]]; then
  echo "invalid macOS signing identifier: $expected_identifier" >&2
  exit 2
fi
if [[ ! -e "$artifact" || -L "$artifact" ]]; then
  echo "macOS signature artifact is missing or unsafe: $artifact" >&2
  exit 1
fi
case "$require_stable_signing" in
  0 | 1) ;;
  *)
    echo "invalid UNPIN_REQUIRE_STABLE_CODESIGN: $require_stable_signing (expected 0 or 1)" >&2
    exit 2
    ;;
esac

# A SHA-1 identity is also the default codesign identity used by the release
# workflow. Keep the explicit variable for clarity, while accepting the
# existing identity variable for local invocations that provide a fingerprint.
if [[ -z "$expected_fingerprint" && "${UNPIN_CODESIGN_IDENTITY:-}" =~ ^[[:xdigit:]]{40}$ ]]; then
  expected_fingerprint="${UNPIN_CODESIGN_IDENTITY}"
fi
if [[ -n "$expected_fingerprint" ]]; then
  expected_fingerprint="$(printf '%s' "$expected_fingerprint" | tr -d ':' | tr '[:lower:]' '[:upper:]')"
  if [[ ! "$expected_fingerprint" =~ ^[[:xdigit:]]{40}$ ]]; then
    echo "UNPIN_CODESIGN_EXPECTED_FINGERPRINT must be a 40-character SHA-1 fingerprint" >&2
    exit 2
  fi
fi

verify_arguments=(--verify --strict --verbose=2)
if [[ -d "$artifact" ]]; then
  verify_arguments+=(--deep)
fi
codesign "${verify_arguments[@]}" "$artifact" >&2

signature_details="$(codesign --display --verbose=4 "$artifact" 2>&1)"
reported_identifier=""
has_adhoc_signature=0
while IFS= read -r detail; do
  case "$detail" in
    Identifier=*) reported_identifier="${detail#Identifier=}" ;;
    Signature=adhoc) has_adhoc_signature=1 ;;
  esac
done <<< "$signature_details"

if [[ "$reported_identifier" != "$expected_identifier" ]]; then
  echo "macOS signature identifier mismatch: expected $expected_identifier, got ${reported_identifier:-<missing>}" >&2
  exit 1
fi
if [[ "$require_stable_signing" == "1" && "$has_adhoc_signature" == "1" ]]; then
  echo "stable macOS signing was required, but codesign produced an ad-hoc signature" >&2
  exit 1
fi

if [[ -n "$expected_fingerprint" ]]; then
  certificate_root="$(mktemp -d)"
  trap 'rm -rf -- "$certificate_root"' EXIT
  certificate_prefix="$certificate_root/certificate"
  if ! codesign --extract-certificates "$certificate_prefix" "$artifact" >/dev/null 2>&1; then
    echo "unable to extract the macOS signing certificate" >&2
    exit 1
  fi

  certificate=""
  for candidate in "$certificate_prefix"0 "$certificate_prefix".0; do
    if [[ -f "$candidate" && ! -L "$candidate" ]]; then
      certificate="$candidate"
      break
    fi
  done
  if [[ -z "$certificate" ]]; then
    echo "macOS signature did not contain an extractable certificate" >&2
    exit 1
  fi

  fingerprint_output=""
  if ! fingerprint_output="$(openssl x509 -inform DER -in "$certificate" -noout -fingerprint -sha1 2>/dev/null)"; then
    fingerprint_output="$(openssl x509 -in "$certificate" -noout -fingerprint -sha1 2>/dev/null)" || {
      echo "unable to read the macOS signing certificate" >&2
      exit 1
    }
  fi
  observed_fingerprint="$(printf '%s\n' "$fingerprint_output" \
    | sed -n 's/^[^=]*=//p' \
    | tr -d ':' \
    | tr '[:lower:]' '[:upper:]' \
    | tr -d '[:space:]')"
  if [[ "$observed_fingerprint" != "$expected_fingerprint" ]]; then
    echo "macOS signing certificate fingerprint mismatch: expected $expected_fingerprint, got ${observed_fingerprint:-<missing>}" >&2
    exit 1
  fi
fi
