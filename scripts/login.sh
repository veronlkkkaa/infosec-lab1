#!/usr/bin/env bash
set -euo pipefail
command -v jq >/dev/null || { printf 'Install jq for this helper script.\n' >&2; exit 1; }
username="${1:-alice}"
read -r -s -p "Password for $username: " password
printf '\n' >&2
printf '%s' "$password" |
  jq -Rs --arg username "$username" '{username: $username, password: .}' |
  curl --fail-with-body -sS http://127.0.0.1:8080/auth/login \
    -H 'Content-Type: application/json' --data-binary @- |
  jq -er '.access_token // error("Login did not return an access token")'
unset password
