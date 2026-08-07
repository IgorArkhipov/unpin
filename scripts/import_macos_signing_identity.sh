#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 0 ]]; then
  echo "usage: scripts/import_macos_signing_identity.sh" >&2
  exit 2
fi

for required_variable in \
  RUNNER_TEMP \
  GITHUB_ENV \
  UNPIN_CODESIGN_IDENTITY \
  UNPIN_MACOS_SIGNING_CERTIFICATE_P12 \
  UNPIN_MACOS_SIGNING_CERTIFICATE_PASSWORD; do
  if [[ -z "${!required_variable:-}" ]]; then
    echo "required macOS signing variable is missing: $required_variable" >&2
    exit 1
  fi
done

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "macOS signing identity import requires Darwin" >&2
  exit 1
fi
if [[ ! -d "$RUNNER_TEMP" || -L "$RUNNER_TEMP" ]]; then
  echo "RUNNER_TEMP is missing or unsafe: $RUNNER_TEMP" >&2
  exit 1
fi
if [[ ! -f "$GITHUB_ENV" || -L "$GITHUB_ENV" ]]; then
  echo "GITHUB_ENV is missing or unsafe: $GITHUB_ENV" >&2
  exit 1
fi

umask 077

signing_keychain="$RUNNER_TEMP/unpin-release-signing.keychain-db"
signing_p12="$RUNNER_TEMP/unpin-release-signing.p12"
search_list_file="$RUNNER_TEMP/unpin-release-signing.keychain-search-list"
if [[ -e "$signing_keychain" || -L "$signing_keychain" ]]; then
  echo "temporary signing Keychain already exists: $signing_keychain" >&2
  exit 1
fi
if [[ -e "$signing_p12" || -L "$signing_p12" ]]; then
  echo "temporary signing certificate already exists: $signing_p12" >&2
  exit 1
fi
if [[ -e "$search_list_file" || -L "$search_list_file" ]]; then
  echo "temporary signing Keychain search-list state already exists: $search_list_file" >&2
  exit 1
fi

restore_search_list() {
  local line
  local -a keychains=()

  [[ -f "$search_list_file" && ! -L "$search_list_file" ]] || return 0

  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    if [[ "$line" == \"*\" ]]; then
      line="${line#\"}"
      line="${line%\"}"
    fi
    [[ -n "$line" ]] && keychains+=("$line")
  done < "$search_list_file"

  if ((${#keychains[@]} == 0)); then
    security list-keychains -d user -s
  else
    security list-keychains -d user -s "${keychains[@]}"
  fi
}

keychain_created=0
cleanup_on_failure() {
  status="$?"
  if [[ "$status" -ne 0 ]]; then
    if ! rm -f -- "$signing_p12"; then
      echo "failed to remove temporary signing certificate: $signing_p12" >&2
    fi
    if [[ "$keychain_created" == "1" ]]; then
      if ! security delete-keychain "$signing_keychain" >/dev/null 2>&1; then
        echo "failed to delete temporary signing Keychain: $signing_keychain" >&2
      fi
    fi
    if [[ -f "$search_list_file" && ! -L "$search_list_file" ]]; then
      if ! restore_search_list; then
        echo "failed to restore the prior user Keychain search list" >&2
      fi
    fi
    if ! rm -f -- "$search_list_file"; then
      echo "failed to remove temporary Keychain search-list state: $search_list_file" >&2
    fi
  fi
  exit "$status"
}
trap cleanup_on_failure EXIT

prior_search_list="$(security list-keychains -d user)"
printf '%s\n' "$prior_search_list" > "$search_list_file"

keychain_password="$(openssl rand -hex 32)"
security create-keychain -p "$keychain_password" "$signing_keychain"
keychain_created=1
security set-keychain-settings -lut 21600 "$signing_keychain"
security unlock-keychain -p "$keychain_password" "$signing_keychain"

printf '%s' "$UNPIN_MACOS_SIGNING_CERTIFICATE_P12" | base64 -D > "$signing_p12"
chmod 600 "$signing_p12"
security import "$signing_p12" \
  -k "$signing_keychain" \
  -P "$UNPIN_MACOS_SIGNING_CERTIFICATE_PASSWORD" \
  -T /usr/bin/codesign \
  -T /usr/bin/security
security set-key-partition-list \
  -S apple-tool:,apple:,codesign: \
  -s \
  -k "$keychain_password" \
  "$signing_keychain" >/dev/null
security list-keychains -d user -s "$signing_keychain"

identity_output="$(security find-identity -v -p codesigning "$signing_keychain")"
if ! identity_hash="$(
  awk '
    /^[[:space:]]*[0-9]+\)[[:space:]]+/ {
      if (NF < 2 || length($2) != 40 || $2 !~ /^[[:xdigit:]]+$/) {
        invalid = 1
        next
      }
      count++
      hash = $2
    }
    /^[[:space:]]*[0-9]+[[:space:]]+valid identities found[[:space:]]*$/ {
      summary_count = $1
    }
    END {
      if (invalid || count != 1 || summary_count != 1) {
        exit 1
      }
      print hash
    }
  ' <<< "$identity_output"
)"; then
  echo "temporary signing Keychain must contain exactly one valid identity with a parseable SHA-1" >&2
  exit 1
fi
if [[ "$identity_hash" != "$UNPIN_CODESIGN_IDENTITY" ]]; then
  echo "temporary signing Keychain does not contain the expected identity" >&2
  exit 1
fi

rm -f -- "$signing_p12"
printf 'UNPIN_SIGNING_KEYCHAIN=%s\n' "$signing_keychain" >> "$GITHUB_ENV"

trap - EXIT
