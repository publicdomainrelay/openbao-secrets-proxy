# OpenBao Secrets Proxy — build plan

Goal: an OpenBao **secrets engine plugin** that is a reverse proxy. It forwards
requests to arbitrary upstream APIs and injects arbitrary secrets into arbitrary
headers (and query parameters). It also runs OAuth 2.0 authorization-code flows
against third-party providers, stores the resulting tokens per OpenBao
**identity entity**, and injects those tokens into proxied requests. Clients are
authenticated to OpenBao with the **OIDC auth engine**, so a caller's OIDC
identity decides which upstream tokens it gets.

Inspiration:
- `atproto-reverse-proxy/src/golang/cmd/oauth-client-webapp/main.go`
  (`oauthRoundTripper` wraps a stored OAuth session as an `http.RoundTripper`;
  `httputil.ReverseProxy` + `Director` injects headers; `/login` + `/callback`
  store sessions).
- `digitalocean-labs/droplet-oidc-poc` (workload identity: OIDC tokens exchanged
  for domain tokens, no static secrets).

## Why a secrets engine plugin

OpenBao plugins of type `secret` are mounted like any secrets engine:

```
bao secrets enable -path=secrets-proxy -plugin-name=secrets-proxy plugin
```

Every HTTP request to `/v1/secrets-proxy/<path>` is routed to the plugin, which
gets `logical.Request` (operation, path, parsed body/query, headers, `EntityID`)
and returns `logical.Response`. OpenBao's HTTP layer honours the magic keys
`http_status_code`, `http_content_type`, `http_raw_body` in the response `Data`
map, so the plugin can return byte-exact upstream responses
(`http/logical.go: respondRaw`). `[]byte` survives the plugin gRPC hop because
`Data` is JSON-marshalled (`sdk/plugin/pb/translation.go`), and a JSON string is
base64-decoded by `respondRaw`.

That gives a real reverse proxy living inside OpenBao, with OpenBao's token and
ACL system as the front door.

## Paths exposed by the plugin

| Path | Operations | Auth | Purpose |
|------|-----------|------|---------|
| `config` | read, update | token | defaults: request timeout, OAuth state TTL, insecure upstreams |
| `routes/?` | list | token | list routes |
| `routes/<name>` | create, read, update, delete | token | upstream URL, header/query injection templates, mode |
| `credentials/?` | list | token | list static credentials |
| `credentials/<name>` | create, read, update, delete | token | static secret values (simple or structured) |
| `oauth/?` | list | token | list OAuth providers |
| `oauth/<name>` | create, read, update, delete | token | provider endpoints, client id/secret, scopes, PKCE |
| `oauth/<name>/login` | read | token | returns `auth_url` + `state`; binds state to caller entity |
| `oauth/callback/<name>` | read | **unauthenticated** | provider redirect target; exchanges code, stores token on the entity |
| `oauth/<name>/token` | read, delete | token | token metadata for caller entity / revoke local copy |
| `proxy/<route>` | read/update/delete/list/head | token | the reverse proxy |
| `proxy/<route>/<rest...>` | read/update/delete/list/head | token | proxy with upstream sub-path |

## Secret reference templates

Route `inject` (headers) and `inject_query` (query params) are
`map[string]string`. Values are templates:

- `$cred:<name>` — static credential value
- `$cred:<name>:<field>` — field of a structured credential
- `$oauth:<name>` — calling entity's OAuth access token (refreshed if needed)
- `$oauth:<name>:access_token|refresh_token|token_type|id_token`
- `$entity:id`, `$entity:name`, `$entity:alias` — caller identity from `SystemView.EntityInfo`
- `$$` — literal `$`
- anything else is a literal

Example:

```hcl
inject = {
  "Authorization" = "Bearer $oauth:github"
  "X-Api-Key"     = "$cred:openai"
  "X-Caller"      = "$entity:name"
}
```

This is how "arbitrary secrets as arbitrary headers" is satisfied.

## OAuth flow (entity-scoped)

1. Client authenticates to OpenBao (OIDC auth engine) and receives a token with
   an `EntityID`.
2. Client calls `GET /v1/secrets-proxy/oauth/<name>/login` with that token. The
   plugin mints a random `state` (+ PKCE verifier), stores
   `oauth/state/<state>` → `{entity_id, provider, redirect_uri, code_verifier}`
   with a TTL, and returns the provider `auth_url`.
3. The user's browser follows `auth_url`, logs in at the provider, and the
   provider redirects to `/v1/secrets-proxy/oauth/callback/<name>?code=..&state=..`
   (an unauthenticated path — the entity is carried in the signed-by-storage
   state).
4. The plugin exchanges the code at `token_url`, stores
   `oauth/token/<name>/entity/<entity_id>` with access/refresh token, expiry and
   scopes, and optionally redirects to a caller-supplied success URL.
5. Later, `proxy/<route>/...` requests from the same entity resolve
   `$oauth:<name>` to that stored token, refreshing it first when it is inside
   the refresh window.

## Files

```
main.go                              plugin entrypoint (plugin.Serve)
internal/secretsproxy/backend.go     factory, Backend, path table
internal/secretsproxy/config.go      config path + storage
internal/secretsproxy/routes.go      route CRUD
internal/secretsproxy/credentials.go credential CRUD
internal/secretsproxy/oauth.go       provider CRUD, login, callback, token
internal/secretsproxy/proxy.go       reverse proxy handler
internal/secretsproxy/template.go    secret reference template renderer
internal/secretsproxy/upstream.go    upstream HTTP call + response mapping
internal/secretsproxy/storage.go     storage keys + typed load/store
internal/oauthclient/client.go       OAuth2 client: auth URL, exchange, refresh
test/integration/harness_test.go     bao dev server + plugin build/register/mount
test/integration/proxy_test.go       static creds, arbitrary headers, errors
test/integration/oauth_test.go       full authorization-code flow + refresh
test/integration/oidc_test.go        OpenBao OIDC auth engine end to end
test/integration/testprovider/       in-process OAuth2/OIDC test provider
examples/echo-upstream/              sample protected upstream API
scripts/build.sh                     build plugin binary
scripts/dev.sh                       run bao dev with plugin dir
```

## Milestones (each ends with a running test)

1. **Skeleton plugin loads.** `main.go` + backend with only `config`. Integration
   test builds the binary, starts `bao server -dev -config=...` with
   `plugin_directory`, registers and mounts, reads `config`.
2. **Routes + credentials + proxy.** Echo upstream; assert injected headers,
   path rewriting, query passthrough, status/body fidelity, error mapping.
3. **OAuth client flow.** In-process test provider; login → callback → token
   stored on entity; proxy injects the token; refresh path exercised.
4. **OIDC auth engine.** OpenBao `oidc` auth method against the in-process OIDC
   provider; a client token from that engine drives the proxy; entity-scoped
   OAuth token lookup proven end to end.
5. **Docs + examples.** README, examples, scripts, `examples/echo-upstream`.

## Known constraints (documented in README)

- POST/PUT/PATCH bodies go through OpenBao's JSON (or form) parser, so non-JSON
  bodies are rejected before the plugin sees them. Query strings on POST are not
  parsed by OpenBao; pass those parameters in the JSON body.
- `OPTIONS` has no `logical.Operation`, so it cannot be proxied.
- Response headers other than `Content-Type`, `Cache-Control`, `Pragma` and
  `WWW-Authenticate` are not surfaced in `raw` mode; use `mode=envelope` to get
  the full header map in JSON.
