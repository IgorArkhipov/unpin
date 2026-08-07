#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 0 ]]; then
  echo "usage: scripts/cleanup_macos_signing_identity.sh" >&2
  exit 2
fi

if [[ -z "${RUNNER_TEMP:-}" ]]; then
  echo "RUNNER_TEMP is required for macOS signing cleanup" >&2
  exit 1
fi
if [[ ! -d "$RUNNER_TEMP" || -L "$RUNNER_TEMP" ]]; then
  echo "RUNNER_TEMP is missing or unsafe: $RUNNER_TEMP" >&2
  exit 1
fi

expected_keychain="$RUNNER_TEMP/unpin-release-signing.keychain-db"
expected_p12="$RUNNER_TEMP/unpin-release-signing.p12"
search_list_file="$RUNNER_TEMP/unpin-release-signing.keychain-search-list"

cleanup_status=0

if [[ -n "${UNPIN_SIGNING_KEYCHAIN:-}" && "$UNPIN_SIGNING_KEYCHAIN" != "$expected_keychain" ]]; then
  echo "refusing to delete unexpected signing Keychain: $UNPIN_SIGNING_KEYCHAIN" >&2
  cleanup_status=1
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

if [[ -L "$expected_keychain" ]]; then
  echo "refusing to delete unsafe temporary signing Keychain path: $expected_keychain" >&2
  cleanup_status=1
elif [[ -e "$expected_keychain" ]]; then
  if ! security delete-keychain "$expected_keychain"; then
    echo "failed to delete temporary signing Keychain: $expected_keychain" >&2
    cleanup_status=1
  fi
fi

if [[ -f "$search_list_file" && ! -L "$search_list_file" ]]; then
  if ! restore_search_list; then
    echo "failed to restore the prior user Keychain search list" >&2
    cleanup_status=1
  fi
elif [[ -L "$search_list_file" ]]; then
  echo "refusing to read unsafe temporary Keychain search-list state: $search_list_file" >&2
  cleanup_status=1
fi

if ! rm -f -- "$expected_p12"; then
  echo "failed to remove temporary signing certificate: $expected_p12" >&2
  cleanup_status=1
fi

if ! rm -f -- "$search_list_file"; then
  echo "failed to remove temporary Keychain search-list state: $search_list_file" >&2
  cleanup_status=1
fi

exit "$cleanup_status"
