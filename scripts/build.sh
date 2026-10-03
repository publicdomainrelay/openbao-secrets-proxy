#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:-"$root/bin"}"

mkdir -p "$out"
cd "$root"
go build -o "$out/openbao-secrets-proxy" .
echo "built $out/openbao-secrets-proxy"
