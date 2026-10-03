#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
plugin_dir="${PLUGIN_DIR:-"$root/bin/plugins"}"
dev_addr="${BAO_DEV_LISTEN_ADDRESS:-127.0.0.1:8200}"
token="${BAO_DEV_ROOT_TOKEN_ID:-root}"

"$root/scripts/build.sh" "$plugin_dir"

config="$(mktemp)"
cat >"$config" <<EOF
plugin_directory = "$plugin_dir"
EOF

export BAO_ADDR="http://$dev_addr"
export BAO_TOKEN="$token"

exec bao server -dev -dev-root-token-id="$token" \
  -dev-listen-address="$dev_addr" -config="$config"
