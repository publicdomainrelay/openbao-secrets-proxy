# openbao-secrets-proxy

An OpenBao **secrets engine plugin** that is a reverse proxy. It forwards
requests to arbitrary upstream APIs and injects arbitrary secrets into
arbitrary headers and query parameters. It also runs OAuth 2.0
authorization-code flows against third-party providers, stores the resulting
tokens against the calling **OpenBao identity entity**, and injects those
tokens into proxied requests.

Clients authenticate to OpenBao with the **OIDC auth engine**, so the same
identity that OpenBao knows from the OIDC login is the identity that selects
which upstream token gets injected. No caller ever handles the upstream
credential.

```
client ──OIDC login──▶ OpenBao ──▶ identity entity
   │                                   ▲
   │  GET /v1/secrets-proxy/proxy/api/  │  $oauth:github resolves to
   └───────────────────────────────────┤  this entity's stored token
                                       │
        ◀── upstream response ──  secrets-proxy engine
                                       │
                                       └──▶ https://api.github.com
                                            Authorization: Bearer gho_…
```

## Why this design

OpenBao secret engines receive every request to their mount as a
`logical.Request` (operation, path, parsed body, entity id) and return a
`logical.Response`. OpenBao's HTTP layer honours the `http_status_code`,
`http_content_type` and `http_raw_body` keys in the response `Data` map
(`http/logical.go: respondRaw`), so the engine can return byte-exact upstream
responses. That makes a real reverse proxy possible *inside* OpenBao, with
OpenBao's token and ACL system as the front door.

Inspired by
[`atproto-reverse-proxy`](https://github.com/publicdomainrelay/atproto-reverse-proxy/blob/main/src/golang/cmd/oauth-client-webapp/main.go)
(`oauthRoundTripper` wrapping a stored OAuth session as an `http.RoundTripper`,
`httputil.ReverseProxy` + `Director` header injection, `/login` + `/callback`
session storage) and
[`droplet-oidc-poc`](https://github.com/digitalocean-labs/droplet-oidc-poc)
(workload identity: OIDC tokens exchanged for domain tokens, no static
secrets).

## Build, register, mount

```sh
./scripts/build.sh                       # writes bin/openbao-secrets-proxy
```

OpenBao must be started with a `plugin_directory`:

```hcl
# openbao.hcl
plugin_directory = "/opt/openbao/plugins"
```

```sh
cp bin/openbao-secrets-proxy /opt/openbao/plugins/
export BAO_ADDR=http://127.0.0.1:8200
export BAO_TOKEN=root

bao plugin register \
  -sha256="$(sha256sum /opt/openbao/plugins/openbao-secrets-proxy | cut -d' ' -f1)" \
  -command=openbao-secrets-proxy \
  secret openbao-secrets-proxy

bao secrets enable -path=secrets-proxy -plugin-name=openbao-secrets-proxy plugin
```

### Allow the client's own headers through (recommended)

OpenBao strips every request header that is not on the mount's passthrough
list. Tune the mount so the engine can see `Content-Type`, `Accept` and the
`X-Proxy-Method` method override:

```sh
bao secrets tune \
  -passthrough-request-headers=Accept \
  -passthrough-request-headers=Accept-Language \
  -passthrough-request-headers=Content-Type \
  -passthrough-request-headers=If-None-Match \
  -passthrough-request-headers=X-Proxy-Method \
  -passthrough-request-headers=X-Forwarded-For \
  secrets-proxy
```

`X-Vault-Token` and `Authorization` are always stripped by OpenBao and can
never reach an upstream.

### Engine configuration

```sh
bao write secrets-proxy/config \
  public_url=http://127.0.0.1:8200 \
  allow_insecure_upstreams=true \
  request_timeout=30 \
  oauth_state_ttl=600
```

| Field | Default | Meaning |
|-------|---------|---------|
| `public_url` | derived from the `Host` header | Externally reachable OpenBao base URL. Used to build OAuth redirect URIs. Set it whenever the engine runs behind a proxy. |
| `allow_insecure_upstreams` | `false` | Permit `http://` upstreams and `insecure_skip_verify` routes. |
| `request_timeout` | `30` | Default upstream timeout, seconds. |
| `oauth_state_ttl` | `600` | Lifetime of an OAuth state nonce, seconds. |
| `user_agent` | `openbao-secrets-proxy` | `User-Agent` sent upstream. |

## Routes: arbitrary secrets into arbitrary headers

A route names an upstream and the templates injected into its requests.

```sh
bao write secrets-proxy/routes/github \
  upstream=https://api.github.com \
  'inject={"Authorization":"Bearer $oauth:github","X-Api-Version":"2022-11-28"}' \
  'inject_query={"access_token":"$cred:fallback-token"}'
```

Then:

```sh
bao read secrets-proxy/proxy/github/user
bao read secrets-proxy/proxy/github/repos/octocat/hello-world
bao list secrets-proxy/proxy/github/user/repos
```

The path after the route name is appended to `upstream`; query parameters on
read/list/delete requests are forwarded; JSON bodies on create/update requests
are forwarded as the upstream body.

Map-typed fields (`inject`, `inject_query`, `extra_headers`, `values`,
`extra_auth_params`, `extra_token_params`) are JSON. The `bao` CLI only decodes
JSON when the whole body comes from a file, so write them with `@`:

```sh
cat >route.json <<'JSON'
{"upstream": "https://api.github.com",
 "inject": {"Authorization": "Bearer $oauth:github"}}
JSON
bao write secrets-proxy/routes/github @route.json
```

Plain string and number fields work inline: `bao write …/routes/r
upstream=https://api.github.com mode=envelope`.

| Field | Default | Meaning |
|-------|---------|---------|
| `upstream` | required | Upstream base URL. A missing scheme means `https://`. |
| `strip_prefix` | `""` | Prefix removed from the proxied sub-path before joining. |
| `inject` | `{}` | Header name to template map. |
| `inject_query` | `{}` | Query parameter name to template map. |
| `extra_headers` | `{}` | Static headers added to every upstream request. |
| `require_entity` | `false` | Reject tokens with no identity entity. |
| `timeout` | engine default | Per-route upstream timeout, seconds. |
| `mode` | `raw` | `raw` returns the upstream body and status unchanged; `envelope` wraps status, headers and body in JSON. |
| `passthrough_query` | `true` | Forward read/list/delete query parameters. |
| `insecure_skip_verify` | `false` | Skip TLS verification for this upstream (needs `allow_insecure_upstreams`). |
| `update_method` | `POST` | Method used for OpenBao update operations; `POST`, `PUT` or `PATCH`. Overridable per request with the `X-Proxy-Method` header. |

### Template reference

Values in `inject`, `inject_query` and static route fields are templates.

| Reference | Resolves to |
|-----------|-------------|
| `$cred:<name>` | Static credential value, or its structured values as JSON. |
| `$cred:<name>:<field>` | One field of a structured credential. |
| `$oauth:<name>` | The calling entity's OAuth access token, refreshed if needed. |
| `$oauth:<name>:access_token` `:refresh_token` `:token_type` `:id_token` | A specific token field. |
| `$entity:id` | The caller's OpenBao entity id. |
| `$entity:name` | The caller's OpenBao entity name. |
| `$entity:alias` | The caller's first entity alias name (for OIDC, the subject). |
| `$$` | A literal `$`. |

Anything that is not a recognised reference is emitted verbatim.

### Static credentials

```sh
bao write secrets-proxy/credentials/openai value=sk-live-…
bao write secrets-proxy/credentials/basic \
  'values={"username":"alice","password":"hunter2"}'
```

Reads never return the secret unless you ask:
`bao read secrets-proxy/credentials/openai reveal=true`.

## OAuth: log in once, inject forever

Register a provider:

```sh
bao write secrets-proxy/oauth/github \
  authorize_url=https://github.com/login/oauth/authorize \
  token_url=https://github.com/login/oauth/access_token \
  client_id=Ov23li… \
  client_secret=… \
  scopes=repo,read:user \
  pkce=true \
  store_mode=entity \
  use_refresh_token=true \
  refresh_window=60
```

| Field | Default | Meaning |
|-------|---------|---------|
| `authorize_url`, `token_url`, `client_id` | required | Provider endpoints and client id. |
| `client_secret` | `""` | Omit for public clients that use PKCE only. |
| `scopes` | `[]` | Comma separated scope list. |
| `redirect_url` | derived | Overrides the callback URL registered with the provider. |
| `audience` | `""` | Sent on both the authorization and token requests (Auth0, DigitalOcean, …). |
| `extra_auth_params`, `extra_token_params` | `{}` | Extra parameters for each leg. |
| `auth_style` | `basic` | `basic` sends client credentials in the `Authorization` header, `body` in the form. |
| `pkce` | `true` | Use PKCE (S256). |
| `store_mode` | `entity` | `entity` keeps one token per identity entity; `shared` keeps a single token. |
| `use_refresh_token` | `true` | Refresh tokens before they expire. |
| `refresh_window` | `60` | Refresh when this many seconds remain. |
| `success_redirect` | `""` | Browser redirect after a successful callback. |
| `disable_refresh_save` | `false` | Use refreshed tokens without persisting them. |

Flow:

```sh
# 1. Authenticated client asks for an authorization URL. The caller's entity
#    is bound to the resulting state nonce.
bao read secrets-proxy/oauth/github/login

# 2. The browser follows data.auth_url, logs in at the provider, and the
#    provider redirects to
#      <public_url>/v1/secrets-proxy/oauth/callback/github?code=…&state=…
#    That path is unauthenticated: the entity travels inside state.

# 3. The token is now stored on the entity.
bao read secrets-proxy/oauth/github/token              # metadata
bao read secrets-proxy/oauth/github/token reveal=true  # with the token
bao delete secrets-proxy/oauth/github/token            # forget it
```

Afterwards every `proxy/…` request from that entity that uses
`$oauth:github` carries that entity's token. A different entity gets a
different token, or a clear error if it has not logged in.

## The full OIDC-client flow

```sh
# OpenBao knows who the client is through the OIDC auth engine.
bao auth enable oidc
bao write auth/oidc/config \
  oidc_discovery_url=https://accounts.example.com \
  oidc_client_id=openbao-client \
  oidc_client_secret=… \
  default_role=default
bao write auth/oidc/role/default \
  allowed_redirect_uris=http://localhost:8250/oidc/callback \
  user_claim=sub \
  oidc_scopes=openid,profile \
  token_policies=secrets-proxy-caller
```

The client logs in with `bao login -method=oidc`, receives a token bound to an
identity entity, runs `secrets-proxy/oauth/<provider>/login` once to store its
upstream token, and from then on every proxied request carries that token.

`test/integration/oidc_test.go` runs exactly this, against an in-process OIDC
provider, and asserts that a second entity cannot spend the first entity's
token.

## ACL policy

OpenBao's own policy engine authorises every path:

```hcl
path "secrets-proxy/proxy/*" {
  capabilities = ["read", "create", "update", "delete", "list"]
}
path "secrets-proxy/oauth/*" {
  capabilities = ["read", "create", "update", "delete", "list"]
}
path "secrets-proxy/routes/*" {
  capabilities = ["read", "list"]
}
```

## Path reference

| Path | Operations | Auth | Purpose |
|------|-----------|------|---------|
| `config` | read, update | token | Engine defaults. |
| `routes/?`, `routes/<name>` | list, create, read, update, delete | token | Proxy routes. |
| `credentials/?`, `credentials/<name>` | list, create, read, update, delete | token | Static secrets. |
| `oauth/?`, `oauth/<name>` | list, create, read, update, delete | token | OAuth providers. |
| `oauth/<name>/login` | read, update | token | Start the flow; returns `auth_url`. |
| `oauth/<name>/token` | read, delete | token | Inspect or drop the caller's token. |
| `oauth/callback/<name>` | read, update | **none** | Provider redirect target. |
| `proxy/<route>`, `proxy/<route>/<rest…>` | read, head, create, update, patch, delete, list | token | The reverse proxy. |

## Examples and tests

```sh
./scripts/build.sh
go test ./...              # unit tests plus the integration suite
```

The integration suite builds the plugin, starts a real `bao server -dev` with a
`plugin_directory`, registers and mounts the engine, tunes it, and drives it
through the `bao` CLI and the HTTP API. It covers header and query injection,
path rewriting, byte-exact response passthrough, envelope mode, entity
templates, the full OAuth authorization-code flow with PKCE and refresh, and
the OIDC-to-OAuth chain.

`scripts/demo.sh` boots a dev server, an echo upstream and a local OAuth
provider, then walks the whole flow and prints each step.

## Limitations

- **Bodies.** OpenBao parses `POST`/`PUT`/`PATCH` bodies as JSON or form data
  before the plugin sees them; non-JSON bodies are rejected by OpenBao itself.
  Query strings on those methods are not parsed either — put those parameters
  in the JSON body.
- **`OPTIONS`.** It has no `logical.Operation`, so it cannot be proxied.
- **Response headers.** `raw` mode surfaces `Content-Type`, `Cache-Control`,
  `Pragma` and `WWW-Authenticate`. Use `mode=envelope` for the full header map.
- **Request headers.** Only headers listed by
  `bao secrets tune -passthrough-request-headers` reach the engine.
- **`bao read` vs. arbitrary APIs.** In `raw` mode the response body *is* the
  upstream body, so `bao read` only renders it nicely when the upstream already
  returns an OpenBao-shaped `{"data": {…}}` document. For any other API use an
  HTTP client:

  ```sh
  curl -s -H "X-Vault-Token: $BAO_TOKEN" \
    "$BAO_ADDR/v1/secrets-proxy/proxy/github/user"
  ```

  `mode=envelope` sidesteps this by always returning
  `{"status_code": …, "headers": …, "body": …}`.

## License

Unlicense (public domain). See `LICENSE`.
