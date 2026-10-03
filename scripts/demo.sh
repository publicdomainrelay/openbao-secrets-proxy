#!/usr/bin/env bash
# Boots a dev OpenBao with the secrets-proxy engine mounted, then walks the
# whole flow: a static credential and an entity-scoped OAuth token injected
# into headers of requests proxied to an echo upstream.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
port="${DEMO_BAO_PORT:-8299}"
upstream_port="${DEMO_UPSTREAM_PORT:-9099}"

export BAO_ADDR="http://127.0.0.1:$port"
export BAO_TOKEN="root"
export BAO_FORMAT=json

cleanup() {
  [[ -n "${bao_pid:-}" ]] && kill "$bao_pid" 2>/dev/null || true
  [[ -n "${echo_pid:-}" ]] && kill "$echo_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }

step "building the plugin and the echo upstream"
mkdir -p "$work/plugins"
"$root/scripts/build.sh" "$work/plugins" >/dev/null
(cd "$root" && go build -o "$work/echo-upstream" ./examples/echo-upstream)

printf 'plugin_directory = "%s"\n' "$work/plugins" >"$work/openbao.hcl"

step "starting the echo upstream on $upstream_port"
"$work/echo-upstream" -addr "127.0.0.1:$upstream_port" >"$work/echo.log" 2>&1 &
echo_pid=$!

step "starting bao server -dev on $port"
bao server -dev -dev-root-token-id=root \
  -dev-listen-address="127.0.0.1:$port" \
  -config="$work/openbao.hcl" >"$work/server.log" 2>&1 &
bao_pid=$!

for _ in $(seq 1 100); do
  if bao status >/dev/null 2>&1; then break; fi
  sleep 0.2
done

step "registering and mounting the engine"
sha="$(sha256sum "$work/plugins/openbao-secrets-proxy" | cut -d' ' -f1)"
bao plugin register -sha256="$sha" -command=openbao-secrets-proxy \
  secret openbao-secrets-proxy >/dev/null
bao secrets enable -path=secrets-proxy -plugin-name=openbao-secrets-proxy plugin >/dev/null
bao secrets tune \
  -passthrough-request-headers=Accept \
  -passthrough-request-headers=Content-Type \
  -passthrough-request-headers=X-Proxy-Method \
  secrets-proxy >/dev/null

bao write secrets-proxy/config \
  public_url="$BAO_ADDR" \
  allow_insecure_upstreams=true >/dev/null

step "storing a static credential"
bao write secrets-proxy/credentials/openai value=sk-live-demo-123 >/dev/null

step "creating a route that injects it as an arbitrary header"
# Map-typed fields are JSON; the bao CLI only decodes JSON from @file.
cat >"$work/route.json" <<EOF
{
  "upstream": "http://127.0.0.1:$upstream_port",
  "inject": {
    "X-Api-Key": "\$cred:openai",
    "Authorization": "Bearer \$cred:openai",
    "X-Static": "demo"
  }
}
EOF
bao write secrets-proxy/routes/echo @"$work/route.json" >/dev/null

step "proxying a request; the echo upstream reports the headers it received"
bao read secrets-proxy/proxy/echo/hello

step "listing routes and credentials"
bao list secrets-proxy/routes
bao list secrets-proxy/credentials

step "envelope mode returns status, headers and body as JSON"
bao write secrets-proxy/routes/enveloped upstream="http://127.0.0.1:$upstream_port" mode=envelope >/dev/null
bao read secrets-proxy/proxy/enveloped/hello

step "done"
