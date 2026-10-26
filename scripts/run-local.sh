#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export LAB_USERNAME="${LAB_USERNAME:-alice}"
export LAB_SECOND_USERNAME="${LAB_SECOND_USERNAME:-bob}"
if [ -z "${JWT_SECRET_BASE64:-}" ]; then
  export JWT_SECRET_BASE64="$(openssl rand -base64 48)"
fi
if [ -z "${LAB_PASSWORD:-}" ]; then
  read -r -s -p "Password for $LAB_USERNAME (15+ characters, <=72 UTF-8 bytes): " LAB_PASSWORD
  printf '\n'
  export LAB_PASSWORD
fi
if [ -z "${LAB_SECOND_PASSWORD:-}" ]; then
  read -r -s -p "Password for $LAB_SECOND_USERNAME (15+ characters, <=72 UTF-8 bytes): " LAB_SECOND_PASSWORD
  printf '\n'
  export LAB_SECOND_PASSWORD
fi
exec ./gradlew --no-daemon bootRun
