# Example: GitHub through the secrets-proxy engine

Two ways to reach `https://api.github.com` without ever handling the GitHub
credential in the calling process.

## A. Static personal access token

```sh
./scripts/build.sh
# register + mount + tune as in README.md

bao write secrets-proxy/credentials/github-pat value=ghp_xxxxxxxxxxxx

cat >github-route.json <<'JSON'
{
  "upstream": "https://api.github.com",
  "inject": {
    "Authorization": "Bearer $cred:github-pat",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
  }
}
JSON
bao write secrets-proxy/routes/github @github-route.json

bao read secrets-proxy/proxy/github/user
bao read secrets-proxy/proxy/github/repos/octocat/hello-world
bao list secrets-proxy/proxy/github/user/repos

# Same thing over HTTP:
curl -s -H "X-Vault-Token: $BAO_TOKEN" \
  "$BAO_ADDR/v1/secrets-proxy/proxy/github/user"
```

The upstream sees `Authorization: Bearer ghp_…`. The caller only ever sent its
OpenBao token. OpenBao ACLs decide who may read
`secrets-proxy/proxy/github/*`.

## B. Per-user GitHub OAuth

Use this when each caller must act as *their own* GitHub account.

```sh
# One-time: an OAuth app on GitHub with callback
#   $BAO_ADDR/v1/secrets-proxy/oauth/github/callback

cat >github-oauth.json <<'JSON'
{
  "authorize_url": "https://github.com/login/oauth/authorize",
  "token_url": "https://github.com/login/oauth/access_token",
  "client_id": "Ov23liXXXXXXXXXXXXXX",
  "client_secret": "…",
  "scopes": ["repo", "read:user"],
  "pkce": true,
  "store_mode": "entity",
  "use_refresh_token": true
}
JSON
bao write secrets-proxy/oauth/github @github-oauth.json

cat >github-oauth-route.json <<'JSON'
{
  "upstream": "https://api.github.com",
  "require_entity": true,
  "inject": {
    "Authorization": "Bearer $oauth:github",
    "Accept": "application/vnd.github+json",
    "X-Caller": "$entity:alias"
  }
}
JSON
bao write secrets-proxy/routes/github @github-oauth-route.json
```

Then each user, logged in to OpenBao through the OIDC auth engine:

```sh
bao read secrets-proxy/oauth/github/login
# open data.auth_url in a browser; GitHub redirects back to
#   $BAO_ADDR/v1/secrets-proxy/oauth/callback/github?code=…&state=…
# which stores that user's token on their OpenBao entity.

bao read secrets-proxy/proxy/github/user
# Authorization: Bearer gho_… — this user's own GitHub token
```

A second user gets their own token, or an error telling them to log in first.
Neither user can spend the other's token: `$oauth:github` resolves through
`req.EntityID`.

## C. OIDC-authenticated machine clients

```sh
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

A workload logs in with `bao login -method=oidc`, runs
`secrets-proxy/oauth/github/login` once, and from then on calls
`secrets-proxy/proxy/github/...` with the injected token. This is the flow the
integration test `TestOIDCClientGetsItsOwnOAuthTokenInjected` exercises against
an in-process OIDC provider.
